package kuznyechik

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type vector struct{ key, in, out []byte }

// readVectors parses Botan's "Key = / In = / Out =" format.
func readVectors(t testing.TB, path string) []vector {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var vs []vector
	var cur vector
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		name, val, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		b := unhex(t, val)
		switch name {
		case "Key":
			cur = vector{key: b}
		case "In":
			cur.in = b
		case "Out":
			cur.out = b
			vs = append(vs, cur)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return vs
}

func checkVectors(t *testing.T, path string, wantMin int) {
	vs := readVectors(t, path)
	if len(vs) < wantMin {
		t.Fatalf("%s: only %d vectors parsed, want at least %d", path, len(vs), wantMin)
	}
	for _, v := range vs {
		c, err := NewCipher(v.key)
		if err != nil {
			t.Fatal(err)
		}
		if len(v.in) != 16 || len(v.out) != 16 {
			t.Fatalf("bad vector lengths %d/%d", len(v.in), len(v.out))
		}
		got := make([]byte, 16)
		c.Encrypt(got, v.in)
		if !bytes.Equal(got, v.out) {
			t.Fatalf("key %x: encrypt = %x, want %x", v.key, got, v.out)
		}
		c.Decrypt(got, v.out)
		if !bytes.Equal(got, v.in) {
			t.Fatalf("key %x: decrypt = %x, want %x", v.key, got, v.in)
		}
	}
	t.Logf("%s: %d vectors", path, len(vs))
}

// Botan's src/tests/data/block/kuznyechik.vec: the RFC 7801 vector and 64
// random ones from Markku-Juhani Saarinen's 8-bit implementation.
func TestBotanVectors(t *testing.T) {
	checkVectors(t, "testdata/botan-kuznyechik.vec", 65)
}

// Differential corpus produced by internal/genbotan from the installed
// `botan cipher` (Kuznyechik/CBC/NoPadding with a zero IV on one block).
func TestBotanDifferential(t *testing.T) {
	checkVectors(t, "testdata/botan-diff.vec", 500)
}

// RFC 7801 section 5.5 and 5.6.
func TestRFC7801(t *testing.T) {
	key := unhex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	pt := unhex(t, "1122334455667700ffeeddccbbaa9988")
	ct := unhex(t, "7f679d90bebc24305a468d42b9d4edcd")
	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 16)
	c.Encrypt(got, pt)
	if !bytes.Equal(got, ct) {
		t.Fatalf("encrypt = %x, want %x", got, ct)
	}
	c.Decrypt(got, ct)
	if !bytes.Equal(got, pt) {
		t.Fatalf("decrypt = %x, want %x", got, pt)
	}
}

// RFC 7801 section 5.1 (S), 5.2 (R) and 5.3 (L).
func TestRFC7801Transformations(t *testing.T) {
	once.Do(initTables)
	for _, v := range [][2]string{
		{"ffeeddccbbaa99881122334455667700", "b66cd8887d38e8d77765aeea0c9a7efc"},
		{"b66cd8887d38e8d77765aeea0c9a7efc", "559d8dd7bd06cbfe7e7b262523280d39"},
		{"559d8dd7bd06cbfe7e7b262523280d39", "0c3322fed531e4630d80ef5c5a81c50b"},
		{"0c3322fed531e4630d80ef5c5a81c50b", "23ae65633f842d29c5df529c13f5acda"},
	} {
		in := unhex(t, v[0])
		for i := range in {
			in[i] = pi[in[i]]
		}
		if hex.EncodeToString(in) != v[1] {
			t.Errorf("S(%s) = %x, want %s", v[0], in, v[1])
		}
		for i := range in {
			in[i] = piInv[in[i]]
		}
		if hex.EncodeToString(in) != v[0] {
			t.Errorf("S^-1 does not invert S on %s", v[0])
		}
	}
	for _, v := range [][2]string{
		{"00000000000000000000000000000100", "94000000000000000000000000000001"},
		{"94000000000000000000000000000001", "a5940000000000000000000000000000"},
		{"a5940000000000000000000000000000", "64a59400000000000000000000000000"},
		{"64a59400000000000000000000000000", "0d64a594000000000000000000000000"},
	} {
		var a [16]byte
		copy(a[:], unhex(t, v[0]))
		rfun(&a)
		if hex.EncodeToString(a[:]) != v[1] {
			t.Errorf("R(%s) = %x, want %s", v[0], a, v[1])
		}
		irfun(&a)
		if hex.EncodeToString(a[:]) != v[0] {
			t.Errorf("R^-1 does not invert R on %s", v[0])
		}
	}
	for _, v := range [][2]string{
		{"64a59400000000000000000000000000", "d456584dd0e3e84cc3166e4b7fa2890d"},
		{"d456584dd0e3e84cc3166e4b7fa2890d", "79d26221b87b584cd42fbc4ffea5de9a"},
		{"79d26221b87b584cd42fbc4ffea5de9a", "0e93691a0cfc60408b7b68f66b513c13"},
		{"0e93691a0cfc60408b7b68f66b513c13", "e6a8094fee0aa204fd97bcb0b44b8580"},
	} {
		var a [16]byte
		copy(a[:], unhex(t, v[0]))
		lbig(&a)
		if hex.EncodeToString(a[:]) != v[1] {
			t.Errorf("L(%s) = %x, want %s", v[0], a, v[1])
		}
		ilbig(&a)
		if hex.EncodeToString(a[:]) != v[0] {
			t.Errorf("L^-1 does not invert L on %s", v[0])
		}
	}
}

// RFC 7801 section 5.4: round constants C_1..C_8 and the ten round keys.
func TestRFC7801KeySchedule(t *testing.T) {
	once.Do(initTables)
	for i, s := range []string{
		"6ea276726c487ab85d27bd10dd849401", "dc87ece4d890f4b3ba4eb92079cbeb02",
		"b2259a96b4d88e0be7690430a44f7f03", "7bcd1b0b73e32ba5b79cb140f2551504",
		"156f6d791fab511deabb0c502fd18105", "a74af7efab73df160dd208608b9efe06",
		"c9e8819dc73ba5ae50f5b570561a6a07", "f6593616e6055689adfba18027aa2a08",
	} {
		var a [16]byte
		copy(a[:], unhex(t, s))
		if words(&a) != rc[i] {
			t.Errorf("C_%d mismatch", i+1)
		}
	}
	b, err := NewCipher(unhex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	c := b.(*block)
	for i, s := range []string{
		"8899aabbccddeeff0011223344556677", "fedcba98765432100123456789abcdef",
		"db31485315694343228d6aef8cc78c44", "3d4553d8e9cfec6815ebadc40a9ffd04",
		"57646468c44a5e28d3e59246f429f1ac", "bd079435165c6432b532e82834da581b",
		"51e640757e8745de705727265a0098b1", "5a7925017b9fdd3ed72a91a22286f984",
		"bb44e25378c73123a5f32f73cdb6e517", "72e9dd7416bcf45b755dbaa88e4a4043",
	} {
		var a [16]byte
		copy(a[:], unhex(t, s))
		if words(&a) != c.ek[i] {
			t.Errorf("K_%d = %x, want %s", i+1, c.ek[i], s)
		}
	}
}

func TestKeySize(t *testing.T) {
	for n := 0; n <= 64; n++ {
		c, err := NewCipher(make([]byte, n))
		if n == 32 {
			if err != nil || c.BlockSize() != 16 {
				t.Fatalf("key %d: %v", n, err)
			}
			continue
		}
		var kse KeySizeError
		if c != nil || !errors.As(err, &kse) || int(kse) != n {
			t.Fatalf("key %d: got %v, %v", n, c, err)
		}
		if !strings.Contains(err.Error(), "invalid key size") {
			t.Fatal(err)
		}
	}
}

func TestPanics(t *testing.T) {
	c, _ := NewCipher(make([]byte, 32))
	for name, f := range map[string]func(){
		"enc short src": func() { c.Encrypt(make([]byte, 16), make([]byte, 15)) },
		"enc short dst": func() { c.Encrypt(make([]byte, 15), make([]byte, 16)) },
		"dec short src": func() { c.Decrypt(make([]byte, 16), make([]byte, 15)) },
		"dec short dst": func() { c.Decrypt(make([]byte, 15), make([]byte, 16)) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
}

func TestInPlace(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	c, _ := NewCipher(key)
	pt := []byte("sixteen byte blk")
	want := make([]byte, 16)
	c.Encrypt(want, pt)
	buf := append([]byte(nil), pt...)
	c.Encrypt(buf, buf)
	if !bytes.Equal(buf, want) {
		t.Fatal("in-place encrypt differs")
	}
	c.Decrypt(buf, buf)
	if !bytes.Equal(buf, pt) {
		t.Fatal("in-place decrypt differs")
	}
}

func roundTrip(t testing.TB, c cipher.Block, p []byte) {
	ct := make([]byte, 16)
	c.Encrypt(ct, p)
	back := make([]byte, 16)
	c.Decrypt(back, ct)
	if !bytes.Equal(back, p) {
		t.Fatalf("round trip failed: %x -> %x -> %x", p, ct, back)
	}
}

func FuzzRoundTrip(f *testing.F) {
	f.Add(make([]byte, 32), make([]byte, 16))
	f.Add(make([]byte, 24), []byte("0123456789abcdef"))
	f.Add(bytes.Repeat([]byte{0xff}, 32), bytes.Repeat([]byte{0xa5}, 16))
	f.Fuzz(func(t *testing.T, key, block []byte) {
		if len(block) < 16 {
			return
		}
		c, err := NewCipher(key)
		if len(key) != 32 {
			if err == nil {
				t.Fatal("bad key accepted")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		roundTrip(t, c, block[:16])
		// Encrypt must be a function of the block alone.
		a, b := make([]byte, 16), make([]byte, 16)
		c.Encrypt(a, block[:16])
		c.Encrypt(b, block[:16])
		if !bytes.Equal(a, b) {
			t.Fatal("encrypt not deterministic")
		}
	})
}

func benchBlock(b *testing.B, dec bool) {
	c, _ := NewCipher(bytes.Repeat([]byte{7}, 32))
	buf := make([]byte, 4096)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for o := 0; o < len(buf); o += 16 {
			if dec {
				c.Decrypt(buf[o:o+16], buf[o:o+16])
			} else {
				c.Encrypt(buf[o:o+16], buf[o:o+16])
			}
		}
	}
}

func BenchmarkEncrypt(b *testing.B) { benchBlock(b, false) }
func BenchmarkDecrypt(b *testing.B) { benchBlock(b, true) }
