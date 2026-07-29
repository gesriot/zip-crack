package crack

import (
	"io"

	"github.com/nwaples/rardecode/v2"
)

// RarArchive verifies passwords for encrypted RAR (RAR3/RAR5) archives.
type RarArchive struct {
	path string
}

// OpenRar prepares a tester for path. The container format (RAR magic) is
// already confirmed by the caller.
func OpenRar(path string) (*RarArchive, error) {
	return &RarArchive{path: path}, nil
}

// rarOpenWithoutPassword reports whether path is fully readable with no
// password at all (i.e. not actually protected).
func rarOpenWithoutPassword(path string) bool {
	r, err := rardecode.OpenReader(path)
	if err != nil {
		return false
	}
	defer r.Close()

	files := 0
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false
		}
		if h.IsDir {
			continue
		}
		if h.Encrypted {
			return false
		}
		n, err := io.Copy(io.Discard, r)
		if err != nil {
			return false
		}
		if n == 0 && h.UnPackedSize > 0 {
			return false
		}
		files++
	}
	return files > 0
}

// TestPassword opens the archive with password and reads the first file
// fully. rardecode validates the file checksum itself while reading, so a
// wrong password (garbage plaintext) surfaces as a read error.
func (s *RarArchive) TestPassword(password string) bool {
	if s == nil || s.path == "" {
		return false
	}
	r, err := rardecode.OpenReader(s.path, rardecode.Password(password))
	if err != nil {
		return false
	}
	defer r.Close()

	for {
		h, err := r.Next()
		if err != nil {
			return false
		}
		if h.IsDir || h.UnPackedSize == 0 {
			// Empty files decrypt to nothing, so they can't confirm or refute
			// the password; keep looking for a file that actually proves it.
			continue
		}
		n, err := io.Copy(io.Discard, r)
		if err != nil {
			return false
		}
		if n == 0 {
			return false
		}
		return true
	}
}
