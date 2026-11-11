<p align="center"><img src="https://raw.githubusercontent.com/go-encryptions/brand/main/social/go-encryptions.png" alt="go-encryptions/kuznyechik" width="720"></p>

# go-encryptions/kuznyechik

[![ci](https://github.com/go-encryptions/kuznyechik/actions/workflows/ci.yml/badge.svg)](https://github.com/go-encryptions/kuznyechik/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-encryptions/kuznyechik.svg)](https://pkg.go.dev/github.com/go-encryptions/kuznyechik)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

Pure-Go **Kuznyechik** block cipher (GOST R 34.12-2015, RFC 7801) as a standard `crypto/cipher.Block`: 16-byte blocks, 32-byte keys only. Table-driven, no cgo, no dependency outside the standard library.

Its first consumer is [`go-fde/veracrypt`](https://github.com/go-fde/veracrypt), which needs Kuznyechik in XTS mode with 256-bit keys (via [`go-encryptions/xts`](https://github.com/go-encryptions/xts)) to open VeraCrypt volumes.

## Install

```sh
go get github.com/go-encryptions/kuznyechik
```

## Usage

```go
import "github.com/go-encryptions/kuznyechik"

block, err := kuznyechik.NewCipher(key) // exactly 32 bytes
if err != nil {
	// a kuznyechik.KeySizeError for any other length
}
block.Encrypt(dst[:16], src[:16]) // dst and src may be the same slice
block.Decrypt(dst[:16], src[:16]) // a buffer under 16 bytes panics
```

The contract is that of `cipher.Block`: in-place operation is allowed and short buffers panic. `kuznyechik.BlockSize` is 16 and `kuznyechik.KeySize` is 32.

## Not constant-time

The S-box and the linear transformation are folded into sixteen 256-entry tables of two 64-bit words (and sixteen more for decryption). Those look-ups use secret-dependent addresses, so **table lookups are not constant-time**: the cipher is exposed to cache-timing attacks by a local attacker. The same holds for the key schedule. Do not use it where that matters.

## Byte order

Blocks and keys are the byte strings of RFC 7801 section 5 exactly as printed there: byte 0 is the leftmost byte (`a_15` in the RFC's notation, which numbers components from the right), the key's first 16 bytes are `K_1` and the last 16 are `K_2`. The RFC example key `8899aabb...cdef` is therefore the byte array `88 99 aa bb ...` and encrypts `1122334455667700ffeeddccbbaa9988` to `7f679d90bebc24305a468d42b9d4edcd`.

VeraCrypt's `src/Crypto/kuznyechik.c` (from kerukuro's cppcrypto, public domain) reads the same arrays and loads them as little-endian 64-bit words. Its generator code is the RFC's `l` written over a byte array in which `a[15]` has coefficient 1 and `a[0]` has coefficient 148, and `R` inserts the new byte at index 0, which is the RFC's string order; its table of round constants starts with `C_1 = 6ea276726c487ab85d27bd10dd849401` (words `0xb87a486c7276a26e`, `0x019484dd10bd275d`). So the RFC's byte order and VeraCrypt's are one and the same, and there is no byte reversal between them. This package loads words explicitly little-endian, so the result is the same on every architecture; CI checks it on big-endian s390x. Botan's `kuznyechik.vec` and `botan cipher` also use this order.

Erratum noted while reading the RFC: section 4.2 prints `32*delta(a_15)` for the second term of `l`; it is `a_14`.

## Verification

- RFC 7801 section 5: the S, R and L examples (5.1 to 5.3), the eight round constants and the ten round keys (5.4), and the encryption and decryption example (5.5, 5.6).
- `testdata/botan-kuznyechik.vec`: Botan's own `src/tests/data/block/kuznyechik.vec`, 65 vectors (the RFC vector and 64 generated with Markku-Juhani Saarinen's 8-bit implementation), encrypted and decrypted.
- `testdata/botan-diff.vec`: a differential corpus of 500 random keys and blocks (the first two keys are all-zero and all-one) generated from the Botan 3.14.1 command line by `internal/genbotan` (`go run ./internal/genbotan`). Regenerating needs `botan` on the `PATH`.
- `FuzzRoundTrip` cross-checks `Encrypt` and `Decrypt` round trips and the refusal of every key length but 32; CI runs it for 60 seconds, and its corpus is in `testdata/fuzz`.
- CI: race detector and a 100 % statement-coverage gate on amd64 and arm64; the same tests under QEMU on big-endian s390x and on riscv64; `govulncheck`.

RFC 8891 (GOST R 34.12-2015 Magma, which carries the GOST R 34.13-2015 examples of that suite) was opened too: it gives Magma vectors only, so it adds nothing for Kuznyechik.

## Implementation

The structure follows RFC 7801: `Pi` of section 4.1; `l`, `R` and `L` of section 4.2 and 4.3 over `GF(2)[x]/(x^8+x^7+x^6+x+1)`; the round constants `C_i = L(Vec_128(i))` and the Feistel key schedule of section 4.4; and `E = X[K10] LSX[K9] ... LSX[K1]` of section 4.5. `L` is linear, so `L(S(x))` is the XOR of sixteen table entries, one per byte position (a straightforward port, which is the equality oracle for any faster kernel to come). Decryption keeps the state in the `L^-1` domain, with `L^-1(K_i)` precomputed, so each round is one table pass. The tables are built once at first use from `Pi` and the RFC's `l`.

Bibliography opened for this work: RFC 7801 (sections 3 to 5); RFC 8891 (checked for Kuznyechik vectors: none); VeraCrypt `src/Crypto/kuznyechik.c` and `kuznyechik.h`; Botan `kuznyechik.vec` and the Botan 3.14.1 command line. The GPL-3 `gogost` was not read.

## Performance

`BenchmarkEncrypt` and `BenchmarkDecrypt` loop the block over a 4 KiB buffer, the shape of one XTS sector, with a 256-bit key and no allocation. The reference is Botan 3.14.1 (`botan speed --buf-size=4096 Kuznyechik`, wrapped as Go benchmarks by `internal/botanbench` so that `abbench` can interleave it). Apple M4 Max (arm64), one core (`GOMAXPROCS=1`), 6 interleaved rounds by `abbench --max-load 8` (it waited for the load to drop and discarded no round), summarised with `benchstat`; both result files hold 12 `^Benchmark` lines.

| 4 KiB, per call | this package | Botan 3.14.1 | ratio |
|---|---|---|---|
| Encrypt | 15.96 µs ± 1 % (245 MiB/s) | 18.14 µs ± 0 % (215 MiB/s) | this package **1.14x faster** |
| Decrypt | 17.29 µs ± 15 % (226 MiB/s) | 20.06 µs ± 0 % (195 MiB/s) | this package **1.16x faster** |

Times are per 4 KiB call, so lower is better; this package allocates nothing. The decrypt spread is wide (one slow round), so read 1.16x as "ahead", not as a precise ratio. `internal/botanbench` reports Botan's rate as ns/op, and `benchstat` does not join benchmarks of two different packages, so the ratios are computed from the two result files' medians. Botan's Kuznyechik is a table implementation too, so this is a like-for-like comparison. No SIMD is used here.

Reproduce: `go test -c -o kuznyechik.test .`, `go test -c -o botan.test ./internal/botanbench`, then `abbench --base ./kuznyechik.test --head ./botan.test --max-load 8 -n 6 -- -test.bench . -test.run '^$'`.

## License

BSD-3-Clause © the go-encryptions/kuznyechik authors.
