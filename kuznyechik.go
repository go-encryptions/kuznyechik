// Package kuznyechik implements the Kuznyechik block cipher of GOST R 34.12-2015
// (RFC 7801) as a crypto/cipher.Block: 16-byte blocks and 32-byte keys.
//
// The implementation is table-driven: the S-box and the linear transformation
// L are folded into sixteen 256-entry tables. Table look-ups index memory with
// secret-dependent addresses, so this package is NOT constant-time.
//
// Byte order: a block or key is the byte string of RFC 7801 section 5 as it is
// written there (the first byte is the leftmost, a_15). veracrypt's
// kuznyechik.c reads the same arrays, so the two agree byte for byte.
package kuznyechik

import (
	"crypto/cipher"
	"encoding/binary"
	"strconv"
	"sync"
)

// BlockSize is the Kuznyechik block size in bytes.
const BlockSize = 16

// KeySize is the only key size in bytes.
const KeySize = 32

// KeySizeError reports a key that is not 32 bytes long.
type KeySizeError int

func (k KeySizeError) Error() string {
	return "kuznyechik: invalid key size " + strconv.Itoa(int(k))
}

// pi is the substitution Pi' of RFC 7801 section 4.1.
var pi = [256]byte{
	252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250,
	218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46,
	153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249,
	24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66,
	139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143,
	160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52,
	44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253,
	58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18,
	191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150,
	41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158,
	178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109,
	84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169,
	62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185,
	3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232,
	40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30,
	0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
	173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165,
	125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172,
	29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225,
	27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144,
	202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9,
	91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166,
	116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57,
	75, 99, 182,
}

// lc holds the coefficients of l (RFC 7801 section 4.2) by array position:
// position i is the RFC's a_(15-i), so lc[0] multiplies a_15. The RFC text
// prints "32*delta(a_15)" for the second term; it must be a_14 (the first term
// is a_15). The RFC section 5 vectors confirm the table below.
var lc = [16]byte{148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1}

// gmul multiplies in GF(2)[x]/(x^8+x^7+x^6+x+1).
func gmul(a, b byte) byte {
	var r byte
	for ; b != 0; b >>= 1 {
		if b&1 != 0 {
			r ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0xc3 // low byte of 0x1c3
		}
	}
	return r
}

func lfun(a *[16]byte) byte {
	var x byte
	for i, c := range lc {
		x ^= gmul(a[i], c)
	}
	return x
}

// rfun is R of the RFC: the new byte enters at position 0.
func rfun(a *[16]byte) {
	x := lfun(a)
	copy(a[1:], a[:15])
	a[0] = x
}

func lbig(a *[16]byte) {
	for i := 0; i < 16; i++ {
		rfun(a)
	}
}

// irfun is R^-1.
func irfun(a *[16]byte) {
	x := a[0]
	copy(a[:15], a[1:])
	a[15] = x
	a[15] = lfun(a)
}

func ilbig(a *[16]byte) {
	for i := 0; i < 16; i++ {
		irfun(a)
	}
}

var (
	once sync.Once
	// piInv is Pi^-1.
	piInv [256]byte
	// te[i][x] = L(S(x) at byte position i); td[i][x] = L^-1(Pi^-1(x) at i).
	te, td [16][256][2]uint64
	// rc[i] = C_(i+1) = L(Vec_128(i+1)) as two little-endian words.
	rc [32][2]uint64
)

func words(a *[16]byte) [2]uint64 {
	return [2]uint64{binary.LittleEndian.Uint64(a[:8]), binary.LittleEndian.Uint64(a[8:])}
}

func initTables() {
	for i, v := range pi {
		piInv[v] = byte(i)
	}
	for pos := 0; pos < 16; pos++ {
		for x := 0; x < 256; x++ {
			var a [16]byte
			a[pos] = pi[x]
			lbig(&a)
			te[pos][x] = words(&a)
			var b [16]byte
			b[pos] = piInv[x]
			ilbig(&b)
			td[pos][x] = words(&b)
		}
	}
	for i := range rc {
		var a [16]byte
		a[15] = byte(i + 1)
		lbig(&a)
		rc[i] = words(&a)
	}
}

// lsEnc returns L(S(x)).
func lsEnc(x1, x2 uint64) (t1, t2 uint64) {
	for i := uint(0); i < 8; i++ {
		a := &te[i][byte(x1>>(8*i))]
		b := &te[8+i][byte(x2>>(8*i))]
		t1 ^= a[0] ^ b[0]
		t2 ^= a[1] ^ b[1]
	}
	return
}

// lsDec returns L^-1(Pi^-1(x)).
func lsDec(x1, x2 uint64) (t1, t2 uint64) {
	for i := uint(0); i < 8; i++ {
		a := &td[i][byte(x1>>(8*i))]
		b := &td[8+i][byte(x2>>(8*i))]
		t1 ^= a[0] ^ b[0]
		t2 ^= a[1] ^ b[1]
	}
	return
}

// linv returns L^-1(x), using td with the S-box folded back out.
func linv(x1, x2 uint64) (t1, t2 uint64) {
	for i := uint(0); i < 8; i++ {
		a := &td[i][pi[byte(x1>>(8*i))]]
		b := &td[8+i][pi[byte(x2>>(8*i))]]
		t1 ^= a[0] ^ b[0]
		t2 ^= a[1] ^ b[1]
	}
	return
}

type block struct {
	ek [10][2]uint64 // K_1..K_10
	dk [10][2]uint64 // dk[0] = K_1; dk[i] = L^-1(K_(i+1)) for i >= 1
}

// NewCipher returns a Kuznyechik cipher.Block for a 32-byte key.
func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != KeySize {
		return nil, KeySizeError(len(key))
	}
	once.Do(initTables)
	c := new(block)
	k := [4]uint64{
		binary.LittleEndian.Uint64(key[0:]), binary.LittleEndian.Uint64(key[8:]),
		binary.LittleEndian.Uint64(key[16:]), binary.LittleEndian.Uint64(key[24:]),
	}
	c.ek[0] = [2]uint64{k[0], k[1]}
	c.ek[1] = [2]uint64{k[2], k[3]}
	// (a1, a0) = (K_(2i-1), K_(2i)); F[k](a1, a0) = (LSX[k](a1) ^ a0, a1).
	a1, a0 := c.ek[0], c.ek[1]
	for i := 0; i < 32; i++ {
		x1, x2 := a1[0]^rc[i][0], a1[1]^rc[i][1]
		t1, t2 := lsEnc(x1, x2)
		a1, a0 = [2]uint64{t1 ^ a0[0], t2 ^ a0[1]}, a1
		if i%8 == 7 {
			c.ek[2+2*(i/8)], c.ek[3+2*(i/8)] = a1, a0
		}
	}
	c.dk[0] = c.ek[0]
	for i := 1; i < 10; i++ {
		t1, t2 := linv(c.ek[i][0], c.ek[i][1])
		c.dk[i] = [2]uint64{t1, t2}
	}
	return c, nil
}

func (c *block) BlockSize() int { return BlockSize }

// Encrypt: E = X[K10] LSX[K9] ... LSX[K1].
func (c *block) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("kuznyechik: input not full block")
	}
	if len(dst) < BlockSize {
		panic("kuznyechik: output not full block")
	}
	x1, x2 := binary.LittleEndian.Uint64(src), binary.LittleEndian.Uint64(src[8:])
	for i := 0; i < 9; i++ {
		x1, x2 = lsEnc(x1^c.ek[i][0], x2^c.ek[i][1])
	}
	binary.LittleEndian.PutUint64(dst, x1^c.ek[9][0])
	binary.LittleEndian.PutUint64(dst[8:], x2^c.ek[9][1])
}

// Decrypt keeps the state in the L^-1 domain so that each round is one table
// pass: with y = L^-1(a), a round is y' = L^-1(Pi^-1(y)) ^ L^-1(K_i).
func (c *block) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("kuznyechik: input not full block")
	}
	if len(dst) < BlockSize {
		panic("kuznyechik: output not full block")
	}
	x1, x2 := binary.LittleEndian.Uint64(src), binary.LittleEndian.Uint64(src[8:])
	y1, y2 := linv(x1, x2)
	y1 ^= c.dk[9][0]
	y2 ^= c.dk[9][1]
	for i := 8; i >= 1; i-- {
		y1, y2 = lsDec(y1, y2)
		y1 ^= c.dk[i][0]
		y2 ^= c.dk[i][1]
	}
	var o1, o2 uint64
	for i := uint(0); i < 8; i++ {
		o1 |= uint64(piInv[byte(y1>>(8*i))]) << (8 * i)
		o2 |= uint64(piInv[byte(y2>>(8*i))]) << (8 * i)
	}
	binary.LittleEndian.PutUint64(dst, o1^c.dk[0][0])
	binary.LittleEndian.PutUint64(dst[8:], o2^c.dk[0][1])
}
