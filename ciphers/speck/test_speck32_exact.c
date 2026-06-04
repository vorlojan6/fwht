#include "speck32_exact.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int check_equal_u32(const char* label, uint32_t actual, uint32_t expected) {
    if (actual != expected) {
        fprintf(stderr, "%s mismatch: got 0x%08x, expected 0x%08x\n", label, actual, expected);
        return 0;
    }
    return 1;
}

static int check_true(const char* label, int condition) {
    if (!condition) {
        fprintf(stderr, "%s failed\n", label);
        return 0;
    }
    return 1;
}

int main(void) {
    static const uint8_t kReferenceKey[SPECK32_EXACT_KEY_BYTES] = {
        0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19
    };
    const uint32_t reference_plaintext = UINT32_C(0x6574694c);
    const uint32_t reference_ciphertext = UINT32_C(0xa86842f2);
    speck32_exact_key_t key_from_bytes;
    speck32_exact_key_t key_from_u64;
    uint32_t selectors[528];
    size_t selector_count;
    size_t index;

    if (!check_true("init key from bytes",
                    speck32_exact_init_key(&key_from_bytes, kReferenceKey, SPECK32_EXACT_MAX_ROUNDS))) {
        return 1;
    }
    if (!check_true("init key from le64",
                    speck32_exact_init_key_le64(&key_from_u64,
                                                UINT64_C(0x1918111009080100),
                                                SPECK32_EXACT_MAX_ROUNDS))) {
        return 1;
    }
    if (!check_true("key schedule equality",
                    memcmp(&key_from_bytes, &key_from_u64, sizeof(key_from_bytes)) == 0)) {
        return 1;
    }

    if (!check_equal_u32("Speck32 encrypt",
                         speck32_exact_encrypt_block(&key_from_bytes, reference_plaintext),
                         reference_ciphertext)) {
        return 1;
    }
    if (!check_equal_u32("Speck32 decrypt",
                         speck32_exact_decrypt_block(&key_from_bytes, reference_ciphertext),
                         reference_plaintext)) {
        return 1;
    }

    selector_count = speck32_exact_enumerate_hamming_weight_one_two(selectors, 528u);
    if (!check_true("selector count", selector_count == speck32_exact_hamming_weight_one_two_count())) {
        return 1;
    }
    if (!check_equal_u32("first selector", selectors[0], UINT32_C(0x00000001))) {
        return 1;
    }
    if (!check_equal_u32("last selector", selectors[selector_count - 1u], UINT32_C(0xc0000000))) {
        return 1;
    }
    for (index = 0u; index < selector_count; ++index) {
        size_t other_index;

        if (!check_true("selector weight", speck32_exact_has_hamming_weight_one_or_two(selectors[index]))) {
            return 1;
        }
        for (other_index = index + 1u; other_index < selector_count; ++other_index) {
            if (!check_true("selector uniqueness", selectors[index] != selectors[other_index])) {
                return 1;
            }
        }
    }

    if (!check_true("domain size", speck32_exact_domain_size() == (((size_t)1) << 32))) {
        return 1;
    }
    if (!check_true("codebook bytes",
                    speck32_exact_required_codebook_bytes() == ((((size_t)1) << 32) * sizeof(uint32_t)))) {
        return 1;
    }
    if (!check_true("spectrum bytes",
                    speck32_exact_required_spectrum_bytes() == ((((size_t)1) << 32) * sizeof(double)))) {
        return 1;
    }

    puts("speck32_exact self-test passed");
    return 0;
}
