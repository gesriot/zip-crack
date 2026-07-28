package crack

import (
	"hash/crc32"
	"io"

	"github.com/bodgit/sevenzip"
)

// SevenZArchive verifies passwords for encrypted 7z archives.
type SevenZArchive struct {
	path string
}

// OpenSevenZ prepares a tester for path. The container format (7z magic) is
// already confirmed by the caller; opening without a password is not
// attempted here because archives with encrypted headers ("encrypt file
// names") fail to list entries at all without the real password.
func OpenSevenZ(path string) (*SevenZArchive, error) {
	return &SevenZArchive{path: path}, nil
}

func sevenZOpenWithoutPassword(path string) bool {
	r, err := sevenzip.OpenReader(path)
	if err != nil {
		return false
	}
	defer r.Close()
	files := 0
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return false
		}
		n, err := io.Copy(io.Discard, rc)
		_ = rc.Close()
		if err != nil {
			return false
		}
		if f.UncompressedSize > 0 && uint64(n) != f.UncompressedSize {
			return false
		}
		if n == 0 && f.UncompressedSize > 0 {
			return false
		}
		files++
	}
	return files > 0
}

// TestPassword opens the archive with password and reads one file fully.
// Wrong AES keys can still yield full-size garbage without I/O error — always
// verify CRC-32 when the header provides one (same idea as Android Commons Compress path).
func (s *SevenZArchive) TestPassword(password string) bool {
	if s == nil || s.path == "" {
		return false
	}
	r, err := sevenzip.OpenReaderWithPassword(s.path, password)
	if err != nil {
		return false
	}
	defer r.Close()

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
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
		if f.UncompressedSize > 0 && uint64(len(body)) != f.UncompressedSize {
			return false
		}
		if len(body) == 0 && f.UncompressedSize > 0 {
			return false
		}
		// CRC32 == 0 is rare for real files; still accept only if size matched and non-empty.
		if f.CRC32 != 0 && crc32.ChecksumIEEE(body) != f.CRC32 {
			return false
		}
		return true
	}
	return false
}
