#include "speck32_exact.h"

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

enum {
    SPECK32_EXACT_ALPHA = 7,
    SPECK32_EXACT_BETA = 2,
    SPECK32_EXACT_KEY_WORDS = 4
};

static const double kSpeck32ExactNormalization = 1.0 / 4294967296.0;

static uint16_t speck32_exact_load_word_le(const uint8_t* src) {
    return (uint16_t)(src[0] | ((uint16_t)src[1] << 8));
}

static uint16_t speck32_exact_rotl16(uint16_t value, unsigned int amount) {
    amount &= 15u;
    if (amount == 0u) {
        return value;
    }
    return (uint16_t)((value << amount) | (value >> (16u - amount)));
}

static uint16_t speck32_exact_rotr16(uint16_t value, unsigned int amount) {
    amount &= 15u;
    if (amount == 0u) {
        return value;
    }
    return (uint16_t)((value >> amount) | (value << (16u - amount)));
}

static unsigned int speck32_exact_lowest_set_bit_index(uint32_t value) {
#if defined(__GNUC__) || defined(__clang__)
    return (unsigned int)__builtin_ctz(value);
#else
    unsigned int index = 0u;

    while ((value & 1u) == 0u) {
        value >>= 1u;
        ++index;
    }
    return index;
#endif
}

static uint64_t speck32_exact_expand_zero_bit(uint64_t compressed_value,
                                              unsigned int zero_bit_index) {
    const uint64_t lower_mask = (zero_bit_index == 0u)
        ? 0u
        : ((UINT64_C(1) << zero_bit_index) - 1u);
    const uint64_t lower = compressed_value & lower_mask;
    const uint64_t upper = compressed_value & ~lower_mask;

    return lower | (upper << 1u);
}

static void speck32_exact_encrypt_round(uint16_t round_key, uint16_t* x, uint16_t* y) {
    *x = speck32_exact_rotr16(*x, SPECK32_EXACT_ALPHA);
    *x = (uint16_t)(*x + *y);
    *x ^= round_key;
    *y = (uint16_t)(speck32_exact_rotl16(*y, SPECK32_EXACT_BETA) ^ *x);
}

static void speck32_exact_decrypt_round(uint16_t round_key, uint16_t* x, uint16_t* y) {
    *y = speck32_exact_rotr16((uint16_t)(*y ^ *x), SPECK32_EXACT_BETA);
    *x = speck32_exact_rotl16((uint16_t)((*x ^ round_key) - *y), SPECK32_EXACT_ALPHA);
}

static fwht_status_t speck32_exact_validate_schedule(const speck32_exact_key_t* schedule) {
    if (schedule == NULL) {
        return FWHT_ERROR_NULL_POINTER;
    }
    if (!speck32_exact_rounds_supported(schedule->rounds)) {
        return FWHT_ERROR_INVALID_ARGUMENT;
    }
    return FWHT_SUCCESS;
}

static fwht_status_t speck32_exact_validate_full_length(size_t length) {
    const size_t domain_size = speck32_exact_domain_size();

    if (domain_size == 0u || length != domain_size) {
        return FWHT_ERROR_INVALID_SIZE;
    }
    return FWHT_SUCCESS;
}

static fwht_status_t speck32_exact_transform_and_normalize(fwht_context_t* ctx,
                                                           double* spectrum,
                                                           size_t spectrum_length) {
    fwht_status_t status;
    long long index;

    status = (ctx != NULL)
        ? fwht_transform_f64(ctx, spectrum, spectrum_length)
        : fwht_f64(spectrum, spectrum_length);
    if (status != FWHT_SUCCESS) {
        return status;
    }

#ifdef _OPENMP
    #pragma omp parallel for schedule(static) if (spectrum_length >= (size_t)(1u << 20))
#endif
    for (index = 0; index < (long long)spectrum_length; ++index) {
        spectrum[(size_t)index] *= kSpeck32ExactNormalization;
    }
    return FWHT_SUCCESS;
}

int speck32_exact_rounds_supported(unsigned int rounds) {
    return rounds >= 1u && rounds <= SPECK32_EXACT_MAX_ROUNDS;
}

int speck32_exact_init_key(speck32_exact_key_t* schedule,
                           const uint8_t master_key[SPECK32_EXACT_KEY_BYTES],
                           unsigned int rounds) {
    uint16_t key_words[SPECK32_EXACT_KEY_WORDS];
    uint16_t l_schedule[SPECK32_EXACT_MAX_ROUNDS + SPECK32_EXACT_KEY_WORDS - 1u];
    unsigned int round_index;

    if (schedule == NULL || master_key == NULL || !speck32_exact_rounds_supported(rounds)) {
        return 0;
    }

    for (round_index = 0; round_index < SPECK32_EXACT_KEY_WORDS; ++round_index) {
        key_words[round_index] = speck32_exact_load_word_le(master_key + 2u * round_index);
    }

    memset(schedule, 0, sizeof(*schedule));
    schedule->rounds = rounds;
    schedule->round_keys[0] = key_words[0];
    for (round_index = 0; round_index < SPECK32_EXACT_KEY_WORDS - 1u; ++round_index) {
        l_schedule[round_index] = key_words[round_index + 1u];
    }

    for (round_index = 0; round_index + 1u < rounds; ++round_index) {
        uint16_t x = l_schedule[round_index];
        uint16_t y = schedule->round_keys[round_index];

        x = speck32_exact_rotr16(x, SPECK32_EXACT_ALPHA);
        x = (uint16_t)(x + y);
        x ^= (uint16_t)round_index;
        y = (uint16_t)(speck32_exact_rotl16(y, SPECK32_EXACT_BETA) ^ x);

        l_schedule[round_index + SPECK32_EXACT_KEY_WORDS - 1u] = x;
        schedule->round_keys[round_index + 1u] = y;
    }

    return 1;
}

int speck32_exact_init_key_le64(speck32_exact_key_t* schedule,
                                uint64_t master_key,
                                unsigned int rounds) {
    uint8_t master_key_bytes[SPECK32_EXACT_KEY_BYTES];
    unsigned int index;

    for (index = 0; index < SPECK32_EXACT_KEY_BYTES; ++index) {
        master_key_bytes[index] = (uint8_t)((master_key >> (8u * index)) & 0xFFu);
    }
    return speck32_exact_init_key(schedule, master_key_bytes, rounds);
}

uint32_t speck32_exact_encrypt_block(const speck32_exact_key_t* schedule, uint32_t plaintext) {
    uint16_t y;
    uint16_t x;
    unsigned int round_index;

    if (schedule == NULL) {
        return 0u;
    }

    y = (uint16_t)(plaintext & 0xFFFFu);
    x = (uint16_t)(plaintext >> 16);
    for (round_index = 0; round_index < schedule->rounds; ++round_index) {
        speck32_exact_encrypt_round(schedule->round_keys[round_index], &x, &y);
    }
    return (uint32_t)y | ((uint32_t)x << 16);
}

uint32_t speck32_exact_decrypt_block(const speck32_exact_key_t* schedule, uint32_t ciphertext) {
    uint16_t y;
    uint16_t x;
    unsigned int round_index;

    if (schedule == NULL) {
        return 0u;
    }

    y = (uint16_t)(ciphertext & 0xFFFFu);
    x = (uint16_t)(ciphertext >> 16);
    for (round_index = schedule->rounds; round_index > 0u; --round_index) {
        speck32_exact_decrypt_round(schedule->round_keys[round_index - 1u], &x, &y);
    }
    return (uint32_t)y | ((uint32_t)x << 16);
}

unsigned int speck32_exact_hamming_weight(uint32_t value) {
#if defined(__GNUC__) || defined(__clang__)
    return (unsigned int)__builtin_popcount(value);
#else
    unsigned int weight = 0u;
    while (value != 0u) {
        value &= value - 1u;
        ++weight;
    }
    return weight;
#endif
}

int speck32_exact_has_hamming_weight_one_or_two(uint32_t value) {
    const unsigned int weight = speck32_exact_hamming_weight(value);
    return weight == 1u || weight == 2u;
}

size_t speck32_exact_hamming_weight_one_two_count(void) {
    return 32u + (32u * 31u) / 2u;
}

size_t speck32_exact_enumerate_hamming_weight_one_two(uint32_t* out_values, size_t capacity) {
    size_t index = 0u;
    unsigned int first_bit;
    unsigned int second_bit;

    for (first_bit = 0u; first_bit < SPECK32_EXACT_BLOCK_BITS; ++first_bit) {
        if (out_values != NULL && index < capacity) {
            out_values[index] = UINT32_C(1) << first_bit;
        }
        ++index;
    }

    for (first_bit = 0u; first_bit < SPECK32_EXACT_BLOCK_BITS; ++first_bit) {
        for (second_bit = first_bit + 1u; second_bit < SPECK32_EXACT_BLOCK_BITS; ++second_bit) {
            if (out_values != NULL && index < capacity) {
                out_values[index] = (UINT32_C(1) << first_bit) | (UINT32_C(1) << second_bit);
            }
            ++index;
        }
    }

    return index;
}

size_t speck32_exact_domain_size(void) {
    if (sizeof(size_t) < sizeof(uint64_t)) {
        return 0u;
    }
    return ((size_t)1u) << SPECK32_EXACT_BLOCK_BITS;
}

size_t speck32_exact_required_codebook_bytes(void) {
    const size_t domain_size = speck32_exact_domain_size();

    if (domain_size == 0u || domain_size > SIZE_MAX / sizeof(uint32_t)) {
        return 0u;
    }
    return domain_size * sizeof(uint32_t);
}

size_t speck32_exact_required_spectrum_bytes(void) {
    const size_t domain_size = speck32_exact_domain_size();

    if (domain_size == 0u || domain_size > SIZE_MAX / sizeof(double)) {
        return 0u;
    }
    return domain_size * sizeof(double);
}

fwht_status_t speck32_exact_build_forward_codebook(const speck32_exact_key_t* schedule,
                                                   uint32_t* codebook,
                                                   size_t codebook_length) {
    fwht_status_t status;
    long long value;

    status = speck32_exact_validate_schedule(schedule);
    if (status != FWHT_SUCCESS) {
        return status;
    }
    if (codebook == NULL) {
        return FWHT_ERROR_NULL_POINTER;
    }
    status = speck32_exact_validate_full_length(codebook_length);
    if (status != FWHT_SUCCESS) {
        return status;
    }

#ifdef _OPENMP
    #pragma omp parallel for schedule(static) if (codebook_length >= (size_t)(1u << 20))
#endif
    for (value = 0; value < (long long)codebook_length; ++value) {
        codebook[(size_t)value] = speck32_exact_encrypt_block(schedule, (uint32_t)(uint64_t)value);
    }
    return FWHT_SUCCESS;
}

fwht_status_t speck32_exact_build_inverse_codebook(const speck32_exact_key_t* schedule,
                                                   uint32_t* codebook,
                                                   size_t codebook_length) {
    fwht_status_t status;
    long long value;

    status = speck32_exact_validate_schedule(schedule);
    if (status != FWHT_SUCCESS) {
        return status;
    }
    if (codebook == NULL) {
        return FWHT_ERROR_NULL_POINTER;
    }
    status = speck32_exact_validate_full_length(codebook_length);
    if (status != FWHT_SUCCESS) {
        return status;
    }

#ifdef _OPENMP
    #pragma omp parallel for schedule(static) if (codebook_length >= (size_t)(1u << 20))
#endif
    for (value = 0; value < (long long)codebook_length; ++value) {
        codebook[(size_t)value] = speck32_exact_decrypt_block(schedule, (uint32_t)(uint64_t)value);
    }
    return FWHT_SUCCESS;
}

fwht_status_t speck32_exact_fill_linear_input_truth_table(const speck32_exact_key_t* schedule,
                                                          uint32_t output_mask,
                                                          const uint32_t* forward_codebook,
                                                          double* truth_table,
                                                          size_t truth_table_length) {
    fwht_status_t status;
    long long value;

    status = speck32_exact_validate_schedule(schedule);
    if (status != FWHT_SUCCESS) {
        return status;
    }
    if (truth_table == NULL) {
        return FWHT_ERROR_NULL_POINTER;
    }
    status = speck32_exact_validate_full_length(truth_table_length);
    if (status != FWHT_SUCCESS) {
        return status;
    }

#ifdef _OPENMP
    #pragma omp parallel for schedule(static) if (truth_table_length >= (size_t)(1u << 20))
#endif
    for (value = 0; value < (long long)truth_table_length; ++value) {
        const uint32_t output = (forward_codebook != NULL)
            ? forward_codebook[(size_t)value]
            : speck32_exact_encrypt_block(schedule, (uint32_t)(uint64_t)value);

        truth_table[(size_t)value] = (speck32_exact_hamming_weight(output & output_mask) & 1u) ? -1.0 : 1.0;
    }
    return FWHT_SUCCESS;
}

fwht_status_t speck32_exact_fill_linear_output_truth_table(const speck32_exact_key_t* schedule,
                                                           uint32_t input_mask,
                                                           const uint32_t* inverse_codebook,
                                                           double* truth_table,
                                                           size_t truth_table_length) {
    fwht_status_t status;
    long long value;

    status = speck32_exact_validate_schedule(schedule);
    if (status != FWHT_SUCCESS) {
        return status;
    }
    if (truth_table == NULL) {
        return FWHT_ERROR_NULL_POINTER;
    }
    status = speck32_exact_validate_full_length(truth_table_length);
    if (status != FWHT_SUCCESS) {
        return status;
    }

#ifdef _OPENMP
    #pragma omp parallel for schedule(static) if (truth_table_length >= (size_t)(1u << 20))
#endif
    for (value = 0; value < (long long)truth_table_length; ++value) {
        const uint32_t input = (inverse_codebook != NULL)
            ? inverse_codebook[(size_t)value]
            : speck32_exact_decrypt_block(schedule, (uint32_t)(uint64_t)value);

        truth_table[(size_t)value] = (speck32_exact_hamming_weight(input & input_mask) & 1u) ? -1.0 : 1.0;
    }
    return FWHT_SUCCESS;
}

fwht_status_t speck32_exact_linear_input_spectrum_from_output_mask(const speck32_exact_key_t* schedule,
                                                                   uint32_t output_mask,
                                                                   const uint32_t* forward_codebook,
                                                                   fwht_context_t* ctx,
                                                                   double* spectrum,
                                                                   size_t spectrum_length) {
    fwht_status_t status = speck32_exact_fill_linear_input_truth_table(schedule,
                                                                       output_mask,
                                                                       forward_codebook,
                                                                       spectrum,
                                                                       spectrum_length);
    if (status != FWHT_SUCCESS) {
        return status;
    }
    return speck32_exact_transform_and_normalize(ctx, spectrum, spectrum_length);
}

fwht_status_t speck32_exact_linear_output_spectrum_from_input_mask(const speck32_exact_key_t* schedule,
                                                                   uint32_t input_mask,
                                                                   const uint32_t* inverse_codebook,
                                                                   fwht_context_t* ctx,
                                                                   double* spectrum,
                                                                   size_t spectrum_length) {
    fwht_status_t status = speck32_exact_fill_linear_output_truth_table(schedule,
                                                                        input_mask,
                                                                        inverse_codebook,
                                                                        spectrum,
                                                                        spectrum_length);
    if (status != FWHT_SUCCESS) {
        return status;
    }
    return speck32_exact_transform_and_normalize(ctx, spectrum, spectrum_length);
}

fwht_status_t speck32_exact_fill_dl_output_histogram_from_input_difference(const speck32_exact_key_t* schedule,
                                                                           uint32_t input_difference,
                                                                           const uint32_t* forward_codebook,
                                                                           double* histogram,
                                                                           size_t histogram_length) {
    fwht_status_t status;
    const uint64_t domain_length = (uint64_t)histogram_length;

    status = speck32_exact_validate_schedule(schedule);
    if (status != FWHT_SUCCESS) {
        return status;
    }
    if (histogram == NULL) {
        return FWHT_ERROR_NULL_POINTER;
    }
    status = speck32_exact_validate_full_length(histogram_length);
    if (status != FWHT_SUCCESS) {
        return status;
    }

    memset(histogram, 0, histogram_length * sizeof(*histogram));
    if (input_difference == 0u) {
        histogram[0] = (double)domain_length;
        return FWHT_SUCCESS;
    }

    {
        const unsigned int split_bit = speck32_exact_lowest_set_bit_index(input_difference);
        const long long pair_count = (long long)(domain_length >> 1u);
        long long pair_index;

#ifdef _OPENMP
        #pragma omp parallel for schedule(static) if (pair_count >= (long long)(1u << 20))
#endif
        for (pair_index = 0; pair_index < pair_count; ++pair_index) {
            const uint64_t value = speck32_exact_expand_zero_bit((uint64_t)pair_index, split_bit);
            const uint64_t paired = value ^ (uint64_t)input_difference;
            uint32_t left;
            uint32_t right;
            uint32_t derivative;

            left = (forward_codebook != NULL)
                ? forward_codebook[(size_t)value]
                : speck32_exact_encrypt_block(schedule, (uint32_t)value);
            right = (forward_codebook != NULL)
                ? forward_codebook[(size_t)paired]
                : speck32_exact_encrypt_block(schedule, (uint32_t)paired);
            derivative = left ^ right;

#ifdef _OPENMP
            #pragma omp atomic update
#endif
            histogram[(size_t)derivative] += 2.0;
        }
    }

    return FWHT_SUCCESS;
}

fwht_status_t speck32_exact_fill_dl_input_histogram_from_output_difference(const speck32_exact_key_t* schedule,
                                                                           uint32_t output_difference,
                                                                           const uint32_t* inverse_codebook,
                                                                           double* histogram,
                                                                           size_t histogram_length) {
    fwht_status_t status;
    const uint64_t domain_length = (uint64_t)histogram_length;

    status = speck32_exact_validate_schedule(schedule);
    if (status != FWHT_SUCCESS) {
        return status;
    }
    if (histogram == NULL) {
        return FWHT_ERROR_NULL_POINTER;
    }
    status = speck32_exact_validate_full_length(histogram_length);
    if (status != FWHT_SUCCESS) {
        return status;
    }

    memset(histogram, 0, histogram_length * sizeof(*histogram));
    if (output_difference == 0u) {
        histogram[0] = (double)domain_length;
        return FWHT_SUCCESS;
    }

    {
        const unsigned int split_bit = speck32_exact_lowest_set_bit_index(output_difference);
        const long long pair_count = (long long)(domain_length >> 1u);
        long long pair_index;

#ifdef _OPENMP
        #pragma omp parallel for schedule(static) if (pair_count >= (long long)(1u << 20))
#endif
        for (pair_index = 0; pair_index < pair_count; ++pair_index) {
            const uint64_t value = speck32_exact_expand_zero_bit((uint64_t)pair_index, split_bit);
            const uint64_t paired = value ^ (uint64_t)output_difference;
            uint32_t left;
            uint32_t right;
            uint32_t derivative;

            left = (inverse_codebook != NULL)
                ? inverse_codebook[(size_t)value]
                : speck32_exact_decrypt_block(schedule, (uint32_t)value);
            right = (inverse_codebook != NULL)
                ? inverse_codebook[(size_t)paired]
                : speck32_exact_decrypt_block(schedule, (uint32_t)paired);
            derivative = left ^ right;

#ifdef _OPENMP
            #pragma omp atomic update
#endif
            histogram[(size_t)derivative] += 2.0;
        }
    }

    return FWHT_SUCCESS;
}

fwht_status_t speck32_exact_dl_output_spectrum_from_input_difference(const speck32_exact_key_t* schedule,
                                                                     uint32_t input_difference,
                                                                     const uint32_t* forward_codebook,
                                                                     fwht_context_t* ctx,
                                                                     double* spectrum,
                                                                     size_t spectrum_length) {
    fwht_status_t status = speck32_exact_fill_dl_output_histogram_from_input_difference(schedule,
                                                                                        input_difference,
                                                                                        forward_codebook,
                                                                                        spectrum,
                                                                                        spectrum_length);
    if (status != FWHT_SUCCESS) {
        return status;
    }
    return speck32_exact_transform_and_normalize(ctx, spectrum, spectrum_length);
}

fwht_status_t speck32_exact_dl_input_spectrum_from_output_difference(const speck32_exact_key_t* schedule,
                                                                     uint32_t output_difference,
                                                                     const uint32_t* inverse_codebook,
                                                                     fwht_context_t* ctx,
                                                                     double* spectrum,
                                                                     size_t spectrum_length) {
    fwht_status_t status = speck32_exact_fill_dl_input_histogram_from_output_difference(schedule,
                                                                                        output_difference,
                                                                                        inverse_codebook,
                                                                                        spectrum,
                                                                                        spectrum_length);
    if (status != FWHT_SUCCESS) {
        return status;
    }
    return speck32_exact_transform_and_normalize(ctx, spectrum, spectrum_length);
}

void speck32_exact_accumulate_squared_values(double* sum_squared,
                                             const double* values,
                                             size_t length) {
    long long index;

    if (sum_squared == NULL || values == NULL) {
        return;
    }

#ifdef _OPENMP
    #pragma omp parallel for schedule(static) if (length >= (size_t)(1u << 20))
#endif
    for (index = 0; index < (long long)length; ++index) {
        const double value = values[(size_t)index];
        sum_squared[(size_t)index] += value * value;
    }
}

void speck32_exact_finish_rms(double* out_rms,
                              const double* sum_squared,
                              size_t length,
                              size_t key_count) {
    long long index;

    if (out_rms == NULL || sum_squared == NULL || key_count == 0u) {
        return;
    }

#ifdef _OPENMP
    #pragma omp parallel for schedule(static) if (length >= (size_t)(1u << 20))
#endif
    for (index = 0; index < (long long)length; ++index) {
        out_rms[(size_t)index] = sqrt(sum_squared[(size_t)index] / (double)key_count);
    }
}
