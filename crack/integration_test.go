package crack

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sample(t *testing.T, name string) string {
	t.Helper()
	// tests run from package dir; samples live in ../dist
	candidates := []string{
		filepath.Join("..", "dist", name),
		filepath.Join("dist", name),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return p
		}
	}
	t.Skipf("sample not found: %s", name)
	return ""
}

func TestProbeAndPassword_ZipCrypto(t *testing.T) {
	path := sample(t, "sample_zipcrypto_4821.zip")
	info, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Backend != BackendZipCrypto {
		t.Fatalf("backend %v", info.Backend)
	}
	if !info.Tester.TestPassword("4821") {
		t.Fatal("4821 rejected")
	}
	if info.Tester.TestPassword("0000") {
		t.Fatal("0000 accepted")
	}
}

func TestProbeAndPassword_ZipAES(t *testing.T) {
	path := sample(t, "sample_zip_aes_4821.zip")
	info, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Backend != BackendZipAES {
		t.Fatalf("backend %v label %s", info.Backend, info.TypeLabel)
	}
	if !info.Tester.TestPassword("4821") {
		t.Fatal("4821 rejected")
	}
	if info.Tester.TestPassword("0000") {
		t.Fatal("0000 accepted")
	}
}

func TestProbeAndPassword_7z(t *testing.T) {
	path := sample(t, "sample_7z_aes_4821.7z")
	info, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Backend != Backend7z {
		t.Fatalf("backend %v", info.Backend)
	}
	if !info.Tester.TestPassword("4821") {
		t.Fatal("4821 rejected")
	}
	if info.Tester.TestPassword("0000") {
		t.Fatal("0000 accepted")
	}
}

func TestProbeAndPassword_OfficeDocx(t *testing.T) {
	path := sample(t, "test.docx")
	info, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Backend != BackendOffice {
		t.Fatalf("backend %v label %s", info.Backend, info.TypeLabel)
	}
	if !info.Tester.TestPassword("5482") {
		t.Fatal("5482 rejected")
	}
	if info.Tester.TestPassword("0000") {
		t.Fatal("0000 accepted")
	}
}

func TestCrackDocxDigits(t *testing.T) {
	path := sample(t, "test.docx")
	info, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	dict := Dict{UseDigits: true, MinLen: 4, MaxLen: 4}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	res, err := Crack(ctx, info.Tester, dict, WorkersFor(info.Backend), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Found || res.Password != "5482" {
		t.Fatalf("got %+v", res)
	}
	t.Logf("docx crack: tried=%d elapsed=%s", res.Tried, res.Elapsed)
}
