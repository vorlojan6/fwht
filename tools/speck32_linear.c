#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

#include "../ciphers/speck/speck32_exact.h"

typedef enum {
    SPECK32_LINEAR_FIXED_INPUT_MASK = 0,
    SPECK32_LINEAR_FIXED_OUTPUT_MASK = 1
} speck32_linear_mode_t;

typedef struct {
    unsigned int rounds;
    uint64_t key;
    uint32_t mask;
    size_t top_k;
    speck32_linear_mode_t mode;
    bool mode_is_set;
    bool use_codebook;
    bool force;
    bool unsafe_memory;
    bool dry_run;
    bool allow_any_mask;
} speck32_linear_options_t;

typedef struct {
    uint32_t mask;
    double correlation;
    double score;
} speck32_linear_top_entry_t;

static void print_usage(const char* program) {
    fprintf(stderr,
            "Usage: %s --rounds <n> --key <hex64> (--input-mask <hex32> | --output-mask <hex32>) [options]\n"
            "\n"
            "Options:\n"
            "  --rounds <n>          Number of Speck32 rounds (1-22).\n"
            "  --key <hex64>        64-bit master key in hexadecimal, for example 0x1918111009080100.\n"
            "  --input-mask <hex32> Fix one input mask and compute all output-mask correlations.\n"
            "  --output-mask <hex32> Fix one output mask and compute all input-mask correlations.\n"
            "  --top <n>            Print the strongest n masks by absolute correlation (default: 16).\n"
            "  --codebook           Precompute the needed codebook instead of streaming. Adds about 16 GiB.\n"
            "  --allow-any-mask     Bypass the Hamming-weight 1 or 2 guideline check.\n"
            "  --dry-run            Print the planned analysis and memory estimate, then exit.\n"
            "  --force              Execute the exact analysis after the memory warning.\n"
            "  --unsafe-memory      Allow execution even when requested memory exceeds detected RAM.\n"
            "  --help               Show this message.\n"
            "\n"
            "Notes:\n"
            "  Exact Speck32 linear analysis allocates a 2^32 double spectrum, about 32 GiB.\n"
            "  Without --force the tool only reports the plan and exits safely.\n"
            "\n"
            "Examples:\n"
            "  %s --rounds 7 --key 0x1918111009080100 --input-mask 0x00000001 --dry-run\n"
            "  %s --rounds 7 --key 0x1918111009080100 --output-mask 0x00010000 --top 8 --force\n",
            program,
            program,
            program);
}

static int parse_u64_hex(const char* text, uint64_t* out_value) {
    char* end = NULL;
    unsigned long long parsed;

    if (text == NULL || out_value == NULL) {
        return 0;
    }

    errno = 0;
    parsed = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') {
        return 0;
    }

    *out_value = (uint64_t)parsed;
    return 1;
}

static int parse_u32_hex(const char* text, uint32_t* out_value) {
    uint64_t parsed;

    if (!parse_u64_hex(text, &parsed) || parsed > UINT32_MAX) {
        return 0;
    }

    *out_value = (uint32_t)parsed;
    return 1;
}

static int parse_unsigned_size(const char* text, size_t* out_value) {
    char* end = NULL;
    unsigned long long parsed;

    if (text == NULL || out_value == NULL) {
        return 0;
    }

    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return 0;
    }

    *out_value = (size_t)parsed;
    return 1;
}

static int parse_rounds(const char* text, unsigned int* out_rounds) {
    size_t parsed;

    if (!parse_unsigned_size(text, &parsed) || parsed > UINT32_MAX) {
        return 0;
    }

    *out_rounds = (unsigned int)parsed;
    return 1;
}

static uint64_t detect_physical_memory_bytes(void) {
#if defined(__APPLE__)
    uint64_t memory_bytes = 0u;
    size_t size = sizeof(memory_bytes);

    if (sysctlbyname("hw.memsize", &memory_bytes, &size, NULL, 0) == 0) {
        return memory_bytes;
    }
    return 0u;
#elif defined(__linux__)
    long page_size = sysconf(_SC_PAGESIZE);
    long page_count = sysconf(_SC_PHYS_PAGES);

    if (page_size <= 0 || page_count <= 0) {
        return 0u;
    }
    return (uint64_t)page_size * (uint64_t)page_count;
#else
    return 0u;
#endif
}

static double bytes_to_gib(uint64_t bytes) {
    return (double)bytes / (1024.0 * 1024.0 * 1024.0);
}

static const char* mode_name(speck32_linear_mode_t mode) {
    return (mode == SPECK32_LINEAR_FIXED_INPUT_MASK)
        ? "fixed input mask -> all output masks"
        : "fixed output mask -> all input masks";
}

static const char* mask_label(speck32_linear_mode_t mode) {
    return (mode == SPECK32_LINEAR_FIXED_INPUT_MASK) ? "input mask" : "output mask";
}

static void print_plan(const speck32_linear_options_t* options,
                       size_t spectrum_bytes,
                       size_t codebook_bytes) {
    const uint64_t physical_memory_bytes = detect_physical_memory_bytes();
    const uint64_t total_bytes = (uint64_t)spectrum_bytes + (uint64_t)codebook_bytes;

    printf("Speck32 exact linear analysis\n");
    printf("  mode: %s\n", mode_name(options->mode));
    printf("  rounds: %u\n", options->rounds);
    printf("  key: 0x%016" PRIx64 "\n", options->key);
    printf("  %s: 0x%08" PRIx32 "\n", mask_label(options->mode), options->mask);
    printf("  spectrum memory: %.2f GiB\n", bytes_to_gib((uint64_t)spectrum_bytes));
    if (options->use_codebook) {
        printf("  codebook memory: %.2f GiB\n", bytes_to_gib((uint64_t)codebook_bytes));
    } else {
        printf("  codebook memory: 0.00 GiB (streaming mode)\n");
    }
    printf("  minimum total memory: %.2f GiB\n", bytes_to_gib(total_bytes));
    if (physical_memory_bytes != 0u) {
        printf("  detected physical memory: %.2f GiB\n", bytes_to_gib(physical_memory_bytes));
        if (total_bytes > physical_memory_bytes) {
            printf("  feasibility: exceeds detected physical memory\n");
        }
    }
    printf("  top results to print: %zu\n", options->top_k);
}

static void format_signed_power_of_two(double value, char* buffer, size_t buffer_size) {
    const char* sign;
    double exponent;

    if (buffer == NULL || buffer_size == 0u) {
        return;
    }
    if (value == 0.0 || !isfinite(value)) {
        snprintf(buffer, buffer_size, "0");
        return;
    }

    sign = (value < 0.0) ? "-" : "+";
    exponent = log2(fabs(value));
    if (fabs(exponent) < 0.00005) {
        exponent = 0.0;
    }
    snprintf(buffer, buffer_size, "%s2^(%.4f)", sign, exponent);
}

static void format_abs_power_of_two(double value, char* buffer, size_t buffer_size) {
    double exponent;

    if (buffer == NULL || buffer_size == 0u) {
        return;
    }
    if (value == 0.0 || !isfinite(value)) {
        snprintf(buffer, buffer_size, "0");
        return;
    }

    exponent = log2(fabs(value));
    if (fabs(exponent) < 0.00005) {
        exponent = 0.0;
    }
    snprintf(buffer, buffer_size, "2^(%.4f)", exponent);
}

static int insert_top_entry(speck32_linear_top_entry_t* entries,
                            size_t entry_count,
                            uint32_t mask,
                            double correlation) {
    size_t index;
    const double score = fabs(correlation);

    if (entry_count == 0u) {
        return 0;
    }
    if (score <= entries[entry_count - 1u].score) {
        return 0;
    }

    entries[entry_count - 1u].mask = mask;
    entries[entry_count - 1u].correlation = correlation;
    entries[entry_count - 1u].score = score;

    for (index = entry_count - 1u; index > 0u; --index) {
        if (entries[index].score <= entries[index - 1u].score) {
            break;
        }

        {
            speck32_linear_top_entry_t tmp = entries[index - 1u];
            entries[index - 1u] = entries[index];
            entries[index] = tmp;
        }
    }

    return 1;
}

static void print_top_results(const speck32_linear_options_t* options,
                              const double* spectrum,
                              size_t spectrum_length) {
    speck32_linear_top_entry_t* entries;
    char signed_buffer[64];
    char abs_buffer[64];
    size_t index;

    entries = (speck32_linear_top_entry_t*)malloc(options->top_k * sizeof(*entries));
    if (entries == NULL) {
        fprintf(stderr, "Error: unable to allocate the result buffer (%s).\n", strerror(errno));
        return;
    }

    for (index = 0u; index < options->top_k; ++index) {
        entries[index].mask = 0u;
        entries[index].correlation = 0.0;
        entries[index].score = -1.0;
    }

    for (index = 0u; index < spectrum_length; ++index) {
        insert_top_entry(entries, options->top_k, (uint32_t)index, spectrum[index]);
    }

    printf("Top %zu correlations by absolute value\n", options->top_k);
    for (index = 0u; index < options->top_k; ++index) {
        if (entries[index].score < 0.0) {
            break;
        }
        format_signed_power_of_two(entries[index].correlation, signed_buffer, sizeof(signed_buffer));
        format_abs_power_of_two(entries[index].correlation, abs_buffer, sizeof(abs_buffer));
        printf("  %2zu. mask=0x%08" PRIx32 " correlation=%s abs=%s\n",
               index + 1u,
               entries[index].mask,
               signed_buffer,
               abs_buffer);
    }

    free(entries);
}

static int parse_options(int argc, char** argv, speck32_linear_options_t* options) {
    int index;

    memset(options, 0, sizeof(*options));
    options->top_k = 16u;

    for (index = 1; index < argc; ++index) {
        const char* arg = argv[index];

        if (strcmp(arg, "--help") == 0) {
            print_usage(argv[0]);
            return 1;
        }
        if (strcmp(arg, "--rounds") == 0) {
            if (++index >= argc || !parse_rounds(argv[index], &options->rounds)) {
                fprintf(stderr, "Error: --rounds expects an integer in [1, 22].\n");
                return -1;
            }
            continue;
        }
        if (strcmp(arg, "--key") == 0) {
            if (++index >= argc || !parse_u64_hex(argv[index], &options->key)) {
                fprintf(stderr, "Error: --key expects a 64-bit hexadecimal value.\n");
                return -1;
            }
            continue;
        }
        if (strcmp(arg, "--input-mask") == 0) {
            if (++index >= argc || !parse_u32_hex(argv[index], &options->mask)) {
                fprintf(stderr, "Error: --input-mask expects a 32-bit hexadecimal value.\n");
                return -1;
            }
            options->mode = SPECK32_LINEAR_FIXED_INPUT_MASK;
            options->mode_is_set = true;
            continue;
        }
        if (strcmp(arg, "--output-mask") == 0) {
            if (++index >= argc || !parse_u32_hex(argv[index], &options->mask)) {
                fprintf(stderr, "Error: --output-mask expects a 32-bit hexadecimal value.\n");
                return -1;
            }
            options->mode = SPECK32_LINEAR_FIXED_OUTPUT_MASK;
            options->mode_is_set = true;
            continue;
        }
        if (strcmp(arg, "--top") == 0) {
            if (++index >= argc || !parse_unsigned_size(argv[index], &options->top_k) || options->top_k == 0u) {
                fprintf(stderr, "Error: --top expects a positive integer.\n");
                return -1;
            }
            continue;
        }
        if (strcmp(arg, "--codebook") == 0) {
            options->use_codebook = true;
            continue;
        }
        if (strcmp(arg, "--force") == 0) {
            options->force = true;
            continue;
        }
        if (strcmp(arg, "--unsafe-memory") == 0) {
            options->unsafe_memory = true;
            continue;
        }
        if (strcmp(arg, "--dry-run") == 0) {
            options->dry_run = true;
            continue;
        }
        if (strcmp(arg, "--allow-any-mask") == 0) {
            options->allow_any_mask = true;
            continue;
        }

        fprintf(stderr, "Error: unknown option '%s'.\n", arg);
        return -1;
    }

    if (!options->mode_is_set) {
        fprintf(stderr, "Error: choose exactly one of --input-mask or --output-mask.\n");
        return -1;
    }
    if (!speck32_exact_rounds_supported(options->rounds)) {
        fprintf(stderr, "Error: --rounds must be in [1, 22].\n");
        return -1;
    }
    if (!options->allow_any_mask && !speck32_exact_has_hamming_weight_one_or_two(options->mask)) {
        fprintf(stderr,
                "Error: the fixed mask must have Hamming weight 1 or 2 under the current guideline.\n"
                "Use --allow-any-mask to bypass this check.\n");
        return -1;
    }

    return 0;
}

int main(int argc, char** argv) {
    speck32_linear_options_t options;
    speck32_exact_key_t schedule;
    fwht_status_t status;
    size_t spectrum_length;
    size_t spectrum_bytes;
    size_t codebook_bytes;
    uint64_t physical_memory_bytes;
    uint64_t total_bytes;
    double* spectrum = NULL;
    uint32_t* codebook = NULL;
    int parse_status;

    parse_status = parse_options(argc, argv, &options);
    if (parse_status > 0) {
        return 0;
    }
    if (parse_status < 0) {
        print_usage(argv[0]);
        return 1;
    }

    if (!speck32_exact_init_key_le64(&schedule, options.key, options.rounds)) {
        fprintf(stderr, "Error: unable to initialize the Speck32 key schedule.\n");
        return 1;
    }

    spectrum_length = speck32_exact_domain_size();
    spectrum_bytes = speck32_exact_required_spectrum_bytes();
    codebook_bytes = options.use_codebook ? speck32_exact_required_codebook_bytes() : 0u;
    total_bytes = (uint64_t)spectrum_bytes + (uint64_t)codebook_bytes;
    physical_memory_bytes = detect_physical_memory_bytes();
    if (spectrum_length == 0u || spectrum_bytes == 0u) {
        fprintf(stderr, "Error: exact Speck32 analysis is unavailable on this platform.\n");
        return 1;
    }

    print_plan(&options, spectrum_bytes, codebook_bytes);
    if (options.dry_run) {
        return 0;
    }
    if (!options.force) {
        fprintf(stderr,
                "Refusing to run without --force because exact Speck32 linear analysis needs a huge buffer.\n");
        return 2;
    }
    if (physical_memory_bytes != 0u && total_bytes > physical_memory_bytes && !options.unsafe_memory) {
        fprintf(stderr,
                "Refusing to run because the requested memory (%.2f GiB) exceeds detected physical memory (%.2f GiB).\n"
                "Use --dry-run to inspect the plan, or add --unsafe-memory if you intentionally want to oversubscribe RAM.\n",
                bytes_to_gib(total_bytes),
                bytes_to_gib(physical_memory_bytes));
        return 2;
    }

    spectrum = (double*)malloc(spectrum_bytes);
    if (spectrum == NULL) {
        fprintf(stderr,
                "Error: unable to allocate the spectrum buffer (%.2f GiB, %s).\n",
                bytes_to_gib((uint64_t)spectrum_bytes),
                strerror(errno));
        return 1;
    }

    if (options.use_codebook) {
        codebook = (uint32_t*)malloc(codebook_bytes);
        if (codebook == NULL) {
            fprintf(stderr,
                    "Error: unable to allocate the codebook buffer (%.2f GiB, %s).\n",
                    bytes_to_gib((uint64_t)codebook_bytes),
                    strerror(errno));
            free(spectrum);
            return 1;
        }

        if (options.mode == SPECK32_LINEAR_FIXED_INPUT_MASK) {
            status = speck32_exact_build_inverse_codebook(&schedule, codebook, spectrum_length);
        } else {
            status = speck32_exact_build_forward_codebook(&schedule, codebook, spectrum_length);
        }
        if (status != FWHT_SUCCESS) {
            fprintf(stderr, "Error: codebook construction failed: %s.\n", fwht_error_string(status));
            free(codebook);
            free(spectrum);
            return 1;
        }
    }

    if (options.mode == SPECK32_LINEAR_FIXED_INPUT_MASK) {
        status = speck32_exact_linear_output_spectrum_from_input_mask(&schedule,
                                                                      options.mask,
                                                                      codebook,
                                                                      NULL,
                                                                      spectrum,
                                                                      spectrum_length);
    } else {
        status = speck32_exact_linear_input_spectrum_from_output_mask(&schedule,
                                                                      options.mask,
                                                                      codebook,
                                                                      NULL,
                                                                      spectrum,
                                                                      spectrum_length);
    }
    if (status != FWHT_SUCCESS) {
        fprintf(stderr, "Error: linear analysis failed: %s.\n", fwht_error_string(status));
        free(codebook);
        free(spectrum);
        return 1;
    }

    print_top_results(&options, spectrum, spectrum_length);

    free(codebook);
    free(spectrum);
    return 0;
}