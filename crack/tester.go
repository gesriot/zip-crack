package crack

import "runtime"

// Backend identifies how passwords are verified.
type Backend int

const (
	// BackendZipCrypto — native ZipCrypto + CRC (fast).
	BackendZipCrypto Backend = iota
	// BackendZipAES — ZIP WinZip AES (and ZipCrypto via yeka/zip).
	BackendZipAES
	// Backend7z — 7z AES (bodgit/sevenzip).
	Backend7z
	// BackendOffice — encrypted DOCX/XLSX/PPTX (MS-OFFCRYPTO agile/standard).
	BackendOffice
)

func (b Backend) String() string {
	switch b {
	case BackendZipCrypto:
		return "native ZipCrypto"
	case BackendZipAES:
		return "zip AES"
	case Backend7z:
		return "7z"
	case BackendOffice:
		return "Office"
	default:
		return "unknown"
	}
}

// PasswordTester verifies a candidate password.
type PasswordTester interface {
	TestPassword(password string) bool
}

// ArchiveInfo is the result of probing a file (mirrors Android ArchiveInfo).
type ArchiveInfo struct {
	DisplayName string
	TypeLabel   string
	Backend     Backend
	SlowPath    bool
	Warning     string
	Tester      PasswordTester
}

// WorkersFor returns a sensible worker count for the backend.
func WorkersFor(b Backend) int {
	n := runtime.NumCPU()
	switch b {
	case BackendZipCrypto:
		w := n * 2
		if w < 4 {
			w = 4
		}
		return w
	default:
		// AES / Office key stretch is CPU-bound; use cores.
		if n < 2 {
			return 2
		}
		return n
	}
}
