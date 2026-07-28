package crack

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestIndexToPassword(t *testing.T) {
	cs := []byte("0123456789")
	if g := IndexToPassword(0, cs, 4); g != "0000" {
		t.Fatalf("got %q", g)
	}
	if g := IndexToPassword(1234, cs, 4); g != "1234" {
		t.Fatalf("got %q", g)
	}
	if g := IndexToPassword(9999, cs, 4); g != "9999" {
		t.Fatalf("got %q", g)
	}
}

func TestCombinationCount(t *testing.T) {
	d := Dict{UseDigits: true, MinLen: 1, MaxLen: 4}
	n, err := d.CombinationCount()
	if err != nil {
		t.Fatal(err)
	}
	if n != 11110 {
		t.Fatalf("got %d", n)
	}
}

func TestZipCryptoCheckByteRoundtrip(t *testing.T) {
	password := "42"
	check := byte(0xAB)
	header := encryptHeader(password, check)
	if !checkZipCrypto(password, header, check) {
		t.Fatal("expected match")
	}
	if checkZipCrypto("43", header, check) {
		t.Fatal("expected mismatch")
	}
}

func encryptHeader(password string, checkByte byte) [12]byte {
	k := initKeys(password)
	var out [12]byte
	plain := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, checkByte}
	for i := 0; i < 12; i++ {
		out[i] = plain[i] ^ k.decryptByte()
		k.update(plain[i])
	}
	return out
}

func TestOpenZipUnencrypted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.zip")
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = OpenZip(path)
	if err != ErrNotEncrypted {
		t.Fatalf("want ErrNotEncrypted, got %v", err)
	}
}

func TestCrackReal7zZipCrypto(t *testing.T) {
	seven := ""
	for _, c := range []string{"7z", "7za"} {
		if p, err := exec.LookPath(c); err == nil {
			seven = p
			break
		}
	}
	if seven == "" {
		t.Skip("7z not installed")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(src, []byte("hello zip crack\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "enc.zip")
	cmd := exec.Command(seven, "a", "-tzip", "-p4821", "-mem=ZipCrypto", archive, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("7z failed: %v\n%s", err, out)
	}

	z, err := OpenZip(archive)
	if err != nil {
		t.Fatal(err)
	}
	if !z.TestPassword("4821") {
		t.Fatal("correct password rejected")
	}
	if z.TestPassword("0000") {
		t.Fatal("wrong password accepted")
	}

	dict := Dict{UseDigits: true, MinLen: 1, MaxLen: 4}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := Crack(ctx, PasswordTester(z), dict, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Found || res.Password != "4821" {
		t.Fatalf("got %+v", res)
	}
}
