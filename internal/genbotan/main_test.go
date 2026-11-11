package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fake(t *testing.T) {
	old := run
	t.Cleanup(func() { run = old })
	run = func(key, block []byte) ([]byte, error) { return bytes.Repeat([]byte{0xab}, 16), nil }
}

func TestGenerate(t *testing.T) {
	fake(t)
	out := filepath.Join(t.TempDir(), "v.vec")
	cmd := RootCmd()
	var so bytes.Buffer
	cmd.SetOut(&so)
	cmd.SetArgs([]string{"-n", "3", "-o", out})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if got := strings.Count(string(b), "\nKey = "); got != 3 {
		t.Fatalf("%d vectors, want 3", got)
	}
	if !strings.Contains(so.String(), "wrote 3 vectors") {
		t.Fatal(so.String())
	}
	if !strings.Contains(string(b), "Key = "+strings.Repeat("0", 64)+"\n") {
		t.Fatal("missing zero key")
	}
}

func TestErrors(t *testing.T) {
	old := run
	defer func() { run = old }()
	run = func(k, b []byte) ([]byte, error) { return nil, errors.New("boom") }
	var buf bytes.Buffer
	if err := generate(&buf, 1); err == nil {
		t.Fatal("want error")
	}
	run = func(k, b []byte) ([]byte, error) { return []byte{1}, nil }
	if err := generate(&buf, 1); err == nil {
		t.Fatal("want short-output error")
	}
	run = old
	// The real runner fails when botan is given an unreadable input path.
	if _, err := run(make([]byte, 3), make([]byte, 16)); err == nil {
		t.Fatal("bad key accepted by runner")
	}
}

func TestOutputUnwritable(t *testing.T) {
	fake(t)
	cmd := RootCmd()
	cmd.SetArgs([]string{"-n", "1", "-o", filepath.Join(t.TempDir(), "no", "such", "v.vec")})
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err == nil {
		t.Fatal("want error")
	}
}

func TestMainExit(t *testing.T) {
	code := -1
	oldExit, oldArgs := osExit, os.Args
	osExit = func(c int) { code = c }
	defer func() { osExit, os.Args = oldExit, oldArgs }()
	os.Args = []string{"genbotan", "--bogus"}
	main()
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	os.Args = []string{"genbotan", "-n", "0", "-o", filepath.Join(t.TempDir(), "x")}
	code = -1
	main()
	if code != -1 {
		t.Fatalf("exit %d", code)
	}
}
