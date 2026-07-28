package crack

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
)

// Traditional PKWARE ZipCrypto: decrypt encryption header + payload, then
// verify by inflating (or storing) and matching CRC-32. Header check-byte
// alone is only 8 bits → ~1/256 false positives; CRC closes that gap.

var (
	ErrNotZip       = errors.New("not a ZIP archive")
	ErrNotEncrypted = errors.New("archive is not password-protected")
	ErrUnsupported  = errors.New("unsupported ZIP encryption (need ZipCrypto; AES not supported yet)")
	ErrNoEntries    = errors.New("ZIP has no file entries")
)

const (
	sigLocalFile  = 0x04034b50
	sigCentralDir = 0x02014b50
	sigEndCentral = 0x06054b50
)

// zipTarget is one encrypted entry used for password checks.
type zipTarget struct {
	method    uint16
	crc32     uint32
	uncomp    uint32
	encHeader [12]byte
	checkByte byte
	// Ciphertext after the 12-byte encryption header.
	data []byte
}

// ZipArchive holds pre-parsed encryption targets from a ZIP file.
type ZipArchive struct {
	path    string
	targets []zipTarget
}

// OpenZip parses the archive (via EOCD + central directory) and loads
// encrypted entry ciphertext for verification.
func OpenZip(path string) (*ZipArchive, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return OpenZipBytes(raw, path)
}

// OpenZipBytes is like OpenZip but with already-read bytes.
func OpenZipBytes(raw []byte, path string) (*ZipArchive, error) {
	targets, err := parseZipTargets(raw)
	if err != nil {
		return nil, err
	}
	return &ZipArchive{path: path, targets: targets}, nil
}

func parseZipTargets(raw []byte) ([]zipTarget, error) {
	eocd, err := findEOCD(raw)
	if err != nil {
		return nil, err
	}
	cdOff := binary.LittleEndian.Uint32(raw[eocd+16 : eocd+20])
	cdSize := binary.LittleEndian.Uint32(raw[eocd+12 : eocd+16])
	nEntries := binary.LittleEndian.Uint16(raw[eocd+10 : eocd+12])
	if uint64(cdOff)+uint64(cdSize) > uint64(len(raw)) {
		return nil, fmt.Errorf("%w: central directory out of range", ErrNotZip)
	}

	var targets []zipTarget
	pos := int(cdOff)
	cdEnd := int(cdOff) + int(cdSize)
	for i := 0; i < int(nEntries); i++ {
		if pos+46 > cdEnd && pos+46 > len(raw) {
			return nil, fmt.Errorf("%w: truncated central directory", ErrNotZip)
		}
		if pos+4 > len(raw) {
			break
		}
		sig := binary.LittleEndian.Uint32(raw[pos : pos+4])
		if sig != sigCentralDir {
			return nil, fmt.Errorf("%w: bad central dir signature", ErrNotZip)
		}
		if pos+46 > len(raw) {
			return nil, fmt.Errorf("%w: truncated central header", ErrNotZip)
		}
		flags := binary.LittleEndian.Uint16(raw[pos+8 : pos+10])
		method := binary.LittleEndian.Uint16(raw[pos+10 : pos+12])
		modTime := binary.LittleEndian.Uint16(raw[pos+12 : pos+14])
		crc := binary.LittleEndian.Uint32(raw[pos+16 : pos+20])
		compSize := binary.LittleEndian.Uint32(raw[pos+20 : pos+24])
		uncomp := binary.LittleEndian.Uint32(raw[pos+24 : pos+28])
		nameLen := int(binary.LittleEndian.Uint16(raw[pos+28 : pos+30]))
		extraLen := int(binary.LittleEndian.Uint16(raw[pos+30 : pos+32]))
		commentLen := int(binary.LittleEndian.Uint16(raw[pos+32 : pos+34]))
		localOff := binary.LittleEndian.Uint32(raw[pos+42 : pos+46])
		pos += 46 + nameLen + extraLen + commentLen

		encrypted := flags&0x1 != 0
		if !encrypted {
			continue
		}
		if method == 99 {
			return nil, ErrUnsupported
		}
		if method != 0 && method != 8 {
			return nil, fmt.Errorf("%w: compression method %d", ErrUnsupported, method)
		}
		if compSize < 12 {
			return nil, fmt.Errorf("encrypted entry too small")
		}

		t, err := loadLocalTarget(raw, int(localOff), method, crc, uncomp, modTime, flags, int(compSize))
		if err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}

	if len(targets) == 0 {
		if nEntries == 0 {
			return nil, ErrNoEntries
		}
		return nil, ErrNotEncrypted
	}
	// Prefer smallest payload first (fast reject).
	best := 0
	for i := 1; i < len(targets); i++ {
		if len(targets[i].data) < len(targets[best].data) {
			best = i
		}
	}
	if best != 0 {
		targets[0], targets[best] = targets[best], targets[0]
	}
	return targets, nil
}

func loadLocalTarget(raw []byte, off int, method uint16, crc, uncomp uint32, modTime, flags uint16, compSize int) (zipTarget, error) {
	var t zipTarget
	if off < 0 || off+30 > len(raw) {
		return t, fmt.Errorf("%w: local header out of range", ErrNotZip)
	}
	if binary.LittleEndian.Uint32(raw[off:off+4]) != sigLocalFile {
		return t, fmt.Errorf("%w: bad local header signature", ErrNotZip)
	}
	nameLen := int(binary.LittleEndian.Uint16(raw[off+26 : off+28]))
	extraLen := int(binary.LittleEndian.Uint16(raw[off+28 : off+30]))
	dataStart := off + 30 + nameLen + extraLen
	dataEnd := dataStart + compSize
	if dataStart < 0 || dataEnd > len(raw) || dataStart+12 > len(raw) {
		return t, fmt.Errorf("%w: local payload out of range", ErrNotZip)
	}
	copy(t.encHeader[:], raw[dataStart:dataStart+12])
	t.data = raw[dataStart+12 : dataEnd]
	t.method = method
	t.crc32 = crc
	t.uncomp = uncomp
	if flags&0x8 != 0 {
		t.checkByte = byte(modTime >> 8)
	} else {
		t.checkByte = byte(crc >> 24)
	}
	return t, nil
}

func findEOCD(raw []byte) (int, error) {
	// EOCD is at least 22 bytes; comment max 65535.
	min := 22
	if len(raw) < min {
		return 0, ErrNotZip
	}
	start := len(raw) - min
	limit := len(raw) - (min + 65535)
	if limit < 0 {
		limit = 0
	}
	for i := start; i >= limit; i-- {
		if binary.LittleEndian.Uint32(raw[i:i+4]) == sigEndCentral {
			return i, nil
		}
	}
	return 0, ErrNotZip
}

// TestPassword returns true if password decrypts and CRC-verifies targets.
// Uses the first (smallest) target for speed; confirms with others if present.
func (z *ZipArchive) TestPassword(password string) bool {
	if z == nil || len(z.targets) == 0 {
		return false
	}
	if !verifyTarget(password, &z.targets[0]) {
		return false
	}
	for i := 1; i < len(z.targets); i++ {
		if !verifyTarget(password, &z.targets[i]) {
			return false
		}
	}
	return true
}

func verifyTarget(password string, t *zipTarget) bool {
	// Fast reject via 12-byte header check byte (~1/256 pass).
	k := initKeys(password)
	var last byte
	for i := 0; i < 12; i++ {
		c := t.encHeader[i] ^ k.decryptByte()
		k.update(c)
		last = c
	}
	if last != t.checkByte {
		return false
	}

	// Decrypt payload with continued keys.
	plain := make([]byte, len(t.data))
	for i := 0; i < len(t.data); i++ {
		c := t.data[i] ^ k.decryptByte()
		k.update(c)
		plain[i] = c
	}

	var body []byte
	switch t.method {
	case 0: // store
		body = plain
	case 8: // deflate
		fr := flate.NewReader(bytes.NewReader(plain))
		var buf bytes.Buffer
		// Limit output to declared size + small slack.
		limit := int64(t.uncomp) + 64
		if limit < 64 {
			limit = 1 << 20
		}
		_, err := io.Copy(&buf, io.LimitReader(fr, limit))
		_ = fr.Close()
		if err != nil {
			return false
		}
		body = buf.Bytes()
	default:
		return false
	}

	if t.uncomp > 0 && uint32(len(body)) != t.uncomp {
		return false
	}
	return crc32.ChecksumIEEE(body) == t.crc32
}

// --- ZipCrypto stream cipher ---

type zipKeys [3]uint32

func initKeys(password string) zipKeys {
	k := zipKeys{0x12345678, 0x23456789, 0x34567890}
	for i := 0; i < len(password); i++ {
		k.update(password[i])
	}
	return k
}

func (k *zipKeys) update(c byte) {
	k[0] = crc32Update(k[0], c)
	k[1] = (k[1] + (k[0] & 0xff)) * 134775813 + 1
	k[2] = crc32Update(k[2], byte(k[1]>>24))
}

func (k *zipKeys) decryptByte() byte {
	temp := k[2] | 2
	return byte((temp * (temp ^ 1)) >> 8)
}

// Kept for unit tests of the keystream.
func checkZipCrypto(password string, header [12]byte, checkByte byte) bool {
	k := initKeys(password)
	var last byte
	for i := 0; i < 12; i++ {
		c := header[i] ^ k.decryptByte()
		k.update(c)
		last = c
	}
	return last == checkByte
}

var crcTable = makeCRCTable()

func makeCRCTable() [256]uint32 {
	var t [256]uint32
	for i := 0; i < 256; i++ {
		c := uint32(i)
		for j := 0; j < 8; j++ {
			if c&1 != 0 {
				c = 0xedb88320 ^ (c >> 1)
			} else {
				c >>= 1
			}
		}
		t[i] = c
	}
	return t
}

func crc32Update(crc uint32, b byte) uint32 {
	return crcTable[byte(crc)^b] ^ (crc >> 8)
}
