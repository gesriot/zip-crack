package crack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	sig7z  = []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}
	sigOLE = []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}
	sigRar = []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07} // "Rar!\x1a\x07" (RAR4 and RAR5 share this prefix)
)

// Probe opens path, detects format/encryption and returns a ready ArchiveInfo.
func Probe(path string) (*ArchiveInfo, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("файл пуст")
	}
	name := filepath.Base(path)
	return ProbeBytes(raw, name, path)
}

// ProbeBytes is like Probe but with already-read bytes.
// path is used for backends that re-open the file (7z).
func ProbeBytes(raw []byte, displayName, path string) (*ArchiveInfo, error) {
	switch {
	case isOLE(raw):
		return probeOffice(raw, displayName)
	case is7z(raw):
		return probe7z(raw, displayName, path)
	case isRar(raw):
		return probeRar(displayName, path)
	case isZip(raw):
		return probeZip(raw, displayName, path)
	default:
		return nil, fmt.Errorf("неизвестный формат. Поддерживаются ZIP, 7z, RAR, encrypted DOCX/XLSX (Office)")
	}
}

func probeOffice(raw []byte, displayName string) (*ArchiveInfo, error) {
	office, err := OpenOffice(raw)
	if err != nil {
		return nil, err
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(displayName), "."))
	kind := "Office"
	switch ext {
	case "docx", "docm", "dotx", "dotm":
		kind = "Word"
	case "xlsx", "xlsm", "xltx", "xltm", "xlsb":
		kind = "Excel"
	case "pptx", "pptm", "potx", "potm":
		kind = "PowerPoint"
	case "doc", "xls", "ppt":
		kind = "Office legacy"
	}
	return &ArchiveInfo{
		DisplayName: displayName,
		TypeLabel:   kind + " · " + office.Detail,
		Backend:     BackendOffice,
		SlowPath:    true,
		Warning:     "Office encryption: ~десятки попыток/с (SHA/AES iterations). Word не требуется.",
		Tester:      office,
	}, nil
}

func probeZip(raw []byte, displayName, path string) (*ArchiveInfo, error) {
	scan := scanZipEncryption(raw)
	switch scan.kind {
	case zipEncNone:
		return nil, ErrNotEncrypted
	case zipEncZipCrypto:
		z, err := OpenZipBytes(raw, path)
		if err != nil {
			return nil, err
		}
		return &ArchiveInfo{
			DisplayName: displayName,
			TypeLabel:   "ZIP · ZipCrypto",
			Backend:     BackendZipCrypto,
			SlowPath:    false,
			Tester:      z,
		}, nil
	case zipEncAES, zipEncMixed:
		label := "ZIP · AES"
		if scan.aesBits > 0 {
			label = fmt.Sprintf("ZIP · AES-%d", scan.aesBits)
		}
		if scan.kind == zipEncMixed {
			label = "ZIP · AES + ZipCrypto"
		}
		z, err := OpenZipAES(raw)
		if err != nil {
			return nil, err
		}
		return &ArchiveInfo{
			DisplayName: displayName,
			TypeLabel:   label,
			Backend:     BackendZipAES,
			SlowPath:    true,
			Warning:     "AES: каждая попытка расшифровывает запись – медленнее ZipCrypto.",
			Tester:      z,
		}, nil
	default:
		return nil, ErrUnsupported
	}
}

func probe7z(raw []byte, displayName, path string) (*ArchiveInfo, error) {
	_ = raw
	// Fully readable without password → not protected.
	if sevenZOpenWithoutPassword(path) {
		return nil, fmt.Errorf("7z-архив не защищён паролем (или пуст)")
	}
	s, err := OpenSevenZ(path)
	if err != nil {
		return nil, err
	}
	return &ArchiveInfo{
		DisplayName: displayName,
		TypeLabel:   "7z · AES",
		Backend:     Backend7z,
		SlowPath:    true,
		Warning:     "7z AES: перебор медленнее native ZipCrypto.",
		Tester:      s,
	}, nil
}

func probeRar(displayName, path string) (*ArchiveInfo, error) {
	// Fully readable without password → not protected.
	if rarOpenWithoutPassword(path) {
		return nil, fmt.Errorf("RAR-архив не защищён паролем (или пуст)")
	}
	s, err := OpenRar(path)
	if err != nil {
		return nil, err
	}
	return &ArchiveInfo{
		DisplayName: displayName,
		TypeLabel:   "RAR · AES",
		Backend:     BackendRar,
		SlowPath:    true,
		Warning:     "RAR AES: перебор медленнее native ZipCrypto.",
		Tester:      s,
	}, nil
}

type zipEncKind int

const (
	zipEncNone zipEncKind = iota
	zipEncZipCrypto
	zipEncAES
	zipEncMixed
)

type zipScan struct {
	kind    zipEncKind
	aesBits int
}

func scanZipEncryption(raw []byte) zipScan {
	eocd, err := findEOCD(raw)
	if err != nil {
		return zipScan{kind: zipEncNone}
	}
	cdOff := int(binary.LittleEndian.Uint32(raw[eocd+16 : eocd+20]))
	nEntries := int(binary.LittleEndian.Uint16(raw[eocd+10 : eocd+12]))
	pos := cdOff
	var zipCrypto, aes bool
	aesBits := 0

	for i := 0; i < nEntries; i++ {
		if pos+46 > len(raw) {
			break
		}
		if binary.LittleEndian.Uint32(raw[pos:pos+4]) != sigCentralDir {
			break
		}
		flags := binary.LittleEndian.Uint16(raw[pos+8 : pos+10])
		method := binary.LittleEndian.Uint16(raw[pos+10 : pos+12])
		nameLen := int(binary.LittleEndian.Uint16(raw[pos+28 : pos+30]))
		extraLen := int(binary.LittleEndian.Uint16(raw[pos+30 : pos+32]))
		commentLen := int(binary.LittleEndian.Uint16(raw[pos+32 : pos+34]))
		extraStart := pos + 46 + nameLen
		if flags&0x1 != 0 {
			if method == 99 {
				aes = true
				if b := parseAESBits(raw, extraStart, extraLen); b > 0 {
					aesBits = b
				}
			} else {
				zipCrypto = true
			}
		}
		pos += 46 + nameLen + extraLen + commentLen
	}

	switch {
	case aes && zipCrypto:
		return zipScan{kind: zipEncMixed, aesBits: aesBits}
	case aes:
		return zipScan{kind: zipEncAES, aesBits: aesBits}
	case zipCrypto:
		return zipScan{kind: zipEncZipCrypto}
	default:
		return zipScan{kind: zipEncNone}
	}
}

func parseAESBits(raw []byte, extraStart, extraLen int) int {
	p := extraStart
	end := extraStart + extraLen
	for p+4 <= end && p+4 <= len(raw) {
		id := binary.LittleEndian.Uint16(raw[p : p+2])
		sz := int(binary.LittleEndian.Uint16(raw[p+2 : p+4]))
		p += 4
		if p+sz > len(raw) {
			break
		}
		if id == 0x9901 && sz >= 7 {
			strength := raw[p+4]
			switch strength {
			case 1:
				return 128
			case 2:
				return 192
			case 3:
				return 256
			}
		}
		p += sz
	}
	return 256
}

func is7z(raw []byte) bool {
	return len(raw) >= 6 && bytes.Equal(raw[:6], sig7z)
}

func isOLE(raw []byte) bool {
	return len(raw) >= 8 && bytes.Equal(raw[:8], sigOLE)
}

func isRar(raw []byte) bool {
	return len(raw) >= len(sigRar) && bytes.Equal(raw[:len(sigRar)], sigRar)
}

func isZip(raw []byte) bool {
	if len(raw) < 4 {
		return false
	}
	sig := binary.LittleEndian.Uint32(raw[:4])
	return sig == sigLocalFile || sig == sigCentralDir || sig == sigEndCentral || sig == 0x08074b50
}
