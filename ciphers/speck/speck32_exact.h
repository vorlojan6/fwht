#ifndef LIBFWHT_CIPHERS_SPECK_SPECK32_EXACT_H
#define LIBFWHT_CIPHERS_SPECK_SPECK32_EXACT_H

#include <stddef.h>
#include <stdint.h>

#include "fwht.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SPECK32_EXACT_BLOCK_BITS 32u
#define SPECK32_EXACT_KEY_BITS 64u
#define SPECK32_EXACT_WORD_BITS 16u
#define SPECK32_EXACT_BLOCK_BYTES 4u
#define SPECK32_EXACT_KEY_BYTES 8u
#define SPECK32_EXACT_MAX_ROUNDS 22u

typedef struct {
    uint16_t round_keys[SPECK32_EXACT_MAX_ROUNDS];
    unsigned int rounds;
} speck32_exact_key_t;

int speck32_exact_rounds_supported(unsigned int rounds);
int speck32_exact_init_key(speck32_exact_key_t* schedule,
                           const uint8_t master_key[SPECK32_EXACT_KEY_BYTES],
                           unsigned int rounds);
int speck32_exact_init_key_le64(speck32_exact_key_t* schedule,
                                uint64_t master_key,
                                unsigned int rounds);

uint32_t speck32_exact_encrypt_block(const speck32_exact_key_t* schedule, uint32_t plaintext);
uint32_t speck32_exact_decrypt_block(const speck32_exact_key_t* schedule, uint32_t ciphertext);

unsigned int speck32_exact_hamming_weight(uint32_t value);
int speck32_exact_has_hamming_weight_one_or_two(uint32_t value);
size_t speck32_exact_hamming_weight_one_two_count(void);
size_t speck32_exact_enumerate_hamming_weight_one_two(uint32_t* out_values, size_t capacity);

size_t speck32_exact_domain_size(void);
size_t speck32_exact_required_codebook_bytes(void);
size_t speck32_exact_required_spectrum_bytes(void);

fwht_status_t speck32_exact_build_forward_codebook(const speck32_exact_key_t* schedule,
                                                   uint32_t* codebook,
                                                   size_t codebook_length);
fwht_status_t speck32_exact_build_inverse_codebook(const speck32_exact_key_t* schedule,
                                                   uint32_t* codebook,
                                                   size_t codebook_length);

fwht_status_t speck32_exact_fill_linear_input_truth_table(const speck32_exact_key_t* schedule,
                                                          uint32_t output_mask,
                                                          const uint32_t* forward_codebook,
                                                          double* truth_table,
                                                          size_t truth_table_length);
fwht_status_t speck32_exact_fill_linear_output_truth_table(const speck32_exact_key_t* schedule,
                                                           uint32_t input_mask,
                                                           const uint32_t* inverse_codebook,
                                                           double* truth_table,
                                                           size_t truth_table_length);
fwht_status_t speck32_exact_linear_input_spectrum_from_output_mask(const speck32_exact_key_t* schedule,
                                                                   uint32_t output_mask,
                                                                   const uint32_t* forward_codebook,
                                                                   fwht_context_t* ctx,
                                                                   double* spectrum,
                                                                   size_t spectrum_length);
fwht_status_t speck32_exact_linear_output_spectrum_from_input_mask(const speck32_exact_key_t* schedule,
                                                                   uint32_t input_mask,
                                                                   const uint32_t* inverse_codebook,
                                                                   fwht_context_t* ctx,
                                                                   double* spectrum,
                                                                   size_t spectrum_length);

fwht_status_t speck32_exact_fill_dl_output_histogram_from_input_difference(const speck32_exact_key_t* schedule,
                                                                           uint32_t input_difference,
                                                                           const uint32_t* forward_codebook,
                                                                           double* histogram,
                                                                           size_t histogram_length);
fwht_status_t speck32_exact_fill_dl_input_histogram_from_output_difference(const speck32_exact_key_t* schedule,
                                                                           uint32_t output_difference,
                                                                           const uint32_t* inverse_codebook,
                                                                           double* histogram,
                                                                           size_t histogram_length);
fwht_status_t speck32_exact_dl_output_spectrum_from_input_difference(const speck32_exact_key_t* schedule,
                                                                     uint32_t input_difference,
                                                                     const uint32_t* forward_codebook,
                                                                     fwht_context_t* ctx,
                                                                     double* spectrum,
                                                                     size_t spectrum_length);
fwht_status_t speck32_exact_dl_input_spectrum_from_output_difference(const speck32_exact_key_t* schedule,
                                                                     uint32_t output_difference,
                                                                     const uint32_t* inverse_codebook,
                                                                     fwht_context_t* ctx,
                                                                     double* spectrum,
                                                                     size_t spectrum_length);

void speck32_exact_accumulate_squared_values(double* sum_squared,
                                             const double* values,
                                             size_t length);
void speck32_exact_finish_rms(double* out_rms,
                              const double* sum_squared,
                              size_t length,
                              size_t key_count);

#ifdef __cplusplus
}
#endif

#endif
