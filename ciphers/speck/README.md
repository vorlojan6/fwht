# Speck32 Exact Tools

This folder has the exact Speck32 code for libfwht.

Files:

- `speck32_exact.h`: public API
- `speck32_exact.c`: exact linear and differential-linear core
- `test_speck32_exact.c`: self-test
- `speck32_linear_sweep.py`: sweep fixed input and output masks
- `speck32_dl_sweep.py`: sweep fixed input differences

## Build

From `code/fwht`:

```bash
make test-speck32 NO_CUDA=1
make speck32-linear NO_CUDA=1
make speck32-dl NO_CUDA=1
```

## Self-Test

```bash
./build/test_speck32_exact
```

## Linear Tool

Show the plan only:

```bash
./build/speck32_linear \
  --rounds 5 \
  --key 0x1918111009080100 \
  --output-mask 0x00000003 \
  --top 8 \
  --dry-run
```

Show the many-key RMS plan with uniformly random master keys:

```bash
./build/speck32_linear \
  --rounds 5 \
  --num-keys 256 \
  --seed 0x1234 \
  --output-mask 0x00000003 \
  --top 8 \
  --dry-run
```

Run the exact search on a machine with enough memory:

```bash
./build/speck32_linear \
  --rounds 5 \
  --key 0x1918111009080100 \
  --output-mask 0x00000003 \
  --top 8 \
  --force
```

## DL Tool

Show the plan only:

```bash
./build/speck32_dl \
  --rounds 5 \
  --key 0x1918111009080100 \
  --input-difference 0x00000001 \
  --top 8 \
  --dry-run
```

Show the many-key RMS plan with uniformly random master keys:

```bash
./build/speck32_dl \
  --rounds 5 \
  --num-keys 256 \
  --seed 0x1234 \
  --input-difference 0x00000001 \
  --top 8 \
  --dry-run
```

Run the exact search on a machine with enough memory:

```bash
./build/speck32_dl \
  --rounds 5 \
  --key 0x1918111009080100 \
  --input-difference 0x00000001 \
  --top 8 \
  --force
```

## Sweep Scripts

Linear sweep:

```bash
python3 ciphers/speck/speck32_linear_sweep.py \
  --rounds 5 \
  --key 0x1918111009080100 \
  --output-dir ./build/speck_runs
```

Each CSV row is one top result for one fixed mask. This writes:

- `speck32_5r_key_1918111009080100_linear_fixed_input_masks_top5.csv`
- `speck32_5r_key_1918111009080100_linear_fixed_output_masks_top5.csv`

Many-key linear sweep:

```bash
python3 ciphers/speck/speck32_linear_sweep.py \
  --rounds 5 \
  --num-keys 256 \
  --seed 0x1234 \
  --output-dir ./build/speck_runs
```

This uses the same random key sample for every fixed mask in the sweep. It writes:

- `speck32_5r_256keys_seed_0000000000001234_linear_fixed_input_masks_top5.csv`
- `speck32_5r_256keys_seed_0000000000001234_linear_fixed_output_masks_top5.csv`

DL sweep:

```bash
python3 ciphers/speck/speck32_dl_sweep.py \
  --rounds 5 \
  --key 0x1918111009080100 \
  --output-dir ./build/speck_runs
```

Each CSV row is one top result for one fixed input difference. This writes:

- `speck32_5r_key_1918111009080100_dl_fixed_input_differences_top5.csv`

Many-key DL sweep:

```bash
python3 ciphers/speck/speck32_dl_sweep.py \
  --rounds 5 \
  --num-keys 256 \
  --seed 0x1234 \
  --output-dir ./build/speck_runs
```

This uses the same random key sample for every fixed input difference in the sweep. It writes:

- `speck32_5r_256keys_seed_0000000000001234_dl_fixed_input_differences_top5.csv`

## Note

The full exact linear and DL runs use a `2^32` double buffer. That is about 32 GiB for the spectrum alone.
For many keys, the tools keep one more `2^32` double array for the running sum of squares, so the minimum becomes about 64 GiB before any codebook.