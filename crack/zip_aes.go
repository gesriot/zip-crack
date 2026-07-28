package crack

import (
	"bytes"
	"hash/crc32"
	"io"

	yzip "github.com/yeka/zip"
)

// ZipAESArchive checks passwords for AES-encrypted (or mixed) ZIP via yeka/zip.
type ZipAESArchive struct {
	data []byte
}

// OpenZipAES keeps the archive bytes for concurrent password tests.
func OpenZipAES(raw []byte) (*ZipAESArchive, error) {
	if len(raw) == 0 {
		return nil, ErrNotZip
	}
	// Smoke: must open as zip.
	r, err := yzip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, err
	}
	hasEnc := false
	for _, f := range r.File {
		if f.IsEncrypted() {
			hasEnc = true
			break
		}
	}
	if !hasEnc {
		return nil, ErrNotEncrypted
	}
	return &ZipAESArchive{data: raw}, nil
}

// TestPassword decrypts at least one non-directory entry and checks size/CRC.
func (z *ZipAESArchive) TestPassword(password string) bool {
	if z == nil || len(z.data) == 0 {
		return false
	}
	r, err := yzip.NewReader(bytes.NewReader(z.data), int64(len(z.data)))
	if err != nil {
		return false
	}
	checked := 0
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if f.IsEncrypted() {
			f.SetPassword(password)
		}
		rc, err := f.Open()
		if err != nil {
			return false
		}
		body, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return false
		}
		if f.UncompressedSize64 > 0 && uint64(len(body)) != f.UncompressedSize64 {
			return false
		}
		// CRC-32 when present (AE-1 stores CRC; AE-2 may zero it).
		if f.CRC32 != 0 && crc32.ChecksumIEEE(body) != f.CRC32 {
			return false
		}
		checked++
		// One good file is enough to accept the password.
		if checked >= 1 {
			return true
		}
	}
	return checked > 0
}
