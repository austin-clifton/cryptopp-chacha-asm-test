# ChaCha ASM Test

I have observed that the ChaCha cipher may have _very_ rarely divergent code paths for AVX vs. SSE.

I have seen this in earlier CryptoPP releases but ran my tests using the latest 8.5.0 release.

I have found on multiple occasions that ChaCha encrypted files decrypt with usually a single flipped bit on other machines. The file will decrypt as expected on the machine that encrypted it.

We run sha256 checks on the decrypted files on both ends. The hashes mismatch as expected when a bit is flipped.

After seeing this behavior in a production environment, I wrote an isolated fuzz test to confirm with garbage files that I could reproduce the behavior.

## Included In This Test

Included are:
- the Visual Studio solution and project used to build the test executable
- the single source file `src/main.cpp`
- a reproducible example in the `example/` directory:
    - a minimal built executable `cryptopp-chacha-asm-test.exe` with hard-coded key, nonce, and filepath
    - the input file which causes the behavior `run_459_file_76.bin`
    - sample encrypted file with AVX `run_459_file_76_avx.bin.enc`
    - sample encrypted file without AVX `run_459_file_76_no_avx.bin.enc`

Included in `main.cpp` are:
- a very minimal test case with a specific key and nonce which produce differing results on (presumably) AVX vs SSE paths
- the source code that was used for the original fuzz test to find a key/nonce/file combo that gives inconsistent behavior, see the `RunFuzzTest()` function.

When run from Visual Studio the process will use the `run/` directory as its working directory.

## Build Details

Cryptopp was built as a static library, x64 multi-threaded debug (\MTd) using Visual Studio 2019 v16.10.0, on Windows 10 Pro v10.0.19043, using the .sln file provided with the source code.

## Machines Tested

Both machines are running Windows 10 Pro v10.0.19043.

CPUs on each machine:
- [AMD Ryzen 3700X](https://www.cpu-world.com/CPUs/Zen/AMD-Ryzen%207%203700X.html)
- [Intel i7-990X](https://www.cpu-world.com/CPUs/Core_i7/Intel-Core%20i7%20Extreme%20Edition%20I7-990X%20AT80613005931AA%20(BX80613I7990X).html)

The 3700X supports AVX, the i7-990X does not.

## Testing Method

The fuzz test in the source code was run on both machines described above until an encrypted sha mismatch was found.

Out of about ~50GB worth of 1MB files which were created and then encrypted on two different machines, only one key + nonce + file combination produced a flipped-bit file.

## Reproduction

The `example/` directory contains a ready-to-run executable. Or, you can build the source yourself using the provided Visual Studio solution. You will need to put a static x64 \MTd `cryptlib.lib` in the `libs/debug/` directory.

The original fuzz test code is commented out. One key/nonce/file combination which produce the flipped bit is hard-coded into `main()`.

The reproducing combo is:
- file `run_459_file_76.bin` (from fuzz test run 459, file 76)
- hex-encoded key `D5B9750A22880B92F1A47BE26CB594F166903B5FC1D79EB99F384AAA356B78D9`
- hex-encoded nonce `3A205D07536CD3CC`

The test will: 
- calculate the sha256 hash of `run_459_file_76.bin`
- encrypt that file to `run_459_file_76.bin.enc`
- calculate the sha256 hash of the encrypted file
- print the original sha256 and the encrypted sha256
- exit

The encrypted files on each machine differ by a single bit at `0x1EBB4`.

The encrypted sha from an AVX-capable CPU is `6fbee484ee64a2ab02235ddf29ca0b61ee3b811d227c2729836d3bd6161c9b18`.

The encrypted sha on non-AVX-capable CPU is `8f16077454f8477594cad4304126b0a6f30c8c4d2536e2441fffd320656e1df1`.

If avx is disabled in CryptoPP using `CRYPTOPP_DISABLE_AVX` and `CRYPTOPP_DISABLE_AVX2`, the resulting encrypted file's sha256 matches on both machines (`8f16...`). You can replace `libs/debug/cryptlib.lib` with `libs/debug/cryptlib-no-avx.lib` to see the encrypted hash change on an AVX-capable machine.