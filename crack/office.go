package crack

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"hash"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/richardlehane/mscfb"
)

// MS-OFFCRYPTO block keys (password verification / key unwrap).
var (
	officeBlock1 = []byte{0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79}
	officeBlock2 = []byte{0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E}
)

const standardSpinCount = 50000

// OfficeArchive verifies passwords for encrypted OOXML (DOCX/XLSX/PPTX).
type OfficeArchive struct {
	Detail string
	verify func(password string) bool
}

// OpenOffice parses EncryptionInfo and returns a password verifier.
func OpenOffice(raw []byte) (*OfficeArchive, error) {
	if !isOLE(raw) {
		return nil, fmt.Errorf("не OLE/Compound (ожидался encrypted Office)")
	}
	doc, err := mscfb.New(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("OLE: %w", err)
	}
	var encInfo []byte
	for {
		f, err := doc.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("OLE walk: %w", err)
		}
		name := f.Name
		// Stream may be "EncryptionInfo" at root.
		if strings.EqualFold(name, "EncryptionInfo") || strings.HasSuffix(strings.ToLower(name), "/encryptioninfo") {
			encInfo, err = io.ReadAll(f)
			if err != nil {
				return nil, fmt.Errorf("EncryptionInfo read: %w", err)
			}
			break
		}
	}
	// mscfb Name is just the entry name, not full path — scan all entries by name.
	if encInfo == nil {
		doc2, err := mscfb.New(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		for {
			f, err := doc2.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if strings.EqualFold(f.Name, "EncryptionInfo") {
				encInfo, err = io.ReadAll(f)
				if err != nil {
					return nil, err
				}
				break
			}
		}
	}
	if len(encInfo) < 8 {
		return nil, fmt.Errorf("OLE без EncryptionInfo – это не password-encrypted Office")
	}

	vMajor := binary.LittleEndian.Uint16(encInfo[0:2])
	vMinor := binary.LittleEndian.Uint16(encInfo[2:4])
	switch {
	case vMajor == 4 && vMinor == 4:
		ag, err := parseAgile(encInfo[8:])
		if err != nil {
			return nil, err
		}
		return &OfficeArchive{
			Detail: ag.detail,
			verify: ag.verify,
		}, nil
	case (vMajor == 2 || vMajor == 3 || vMajor == 4) && vMinor == 2:
		st, err := parseStandard(encInfo)
		if err != nil {
			return nil, err
		}
		return &OfficeArchive{
			Detail: st.detail,
			verify: st.verify,
		}, nil
	default:
		return nil, fmt.Errorf("неподдерживаемая версия EncryptionInfo: %d.%d", vMajor, vMinor)
	}
}

// TestPassword implements PasswordTester.
func (o *OfficeArchive) TestPassword(password string) bool {
	if o == nil || o.verify == nil {
		return false
	}
	return o.verify(password)
}

type agileInfo struct {
	spinCount       uint32
	salt            []byte
	hashAlg         string
	keyBits         int
	encVerifierIn   []byte
	encVerifierHash []byte
	detail          string
}

func (a *agileInfo) verify(password string) bool {
	digest, err := a.iteratedHash(password)
	if err != nil {
		return false
	}
	key1, err := a.blockKey(digest, officeBlock1)
	if err != nil {
		return false
	}
	key2, err := a.blockKey(digest, officeBlock2)
	if err != nil {
		return false
	}
	verifierIn, ok := aesCBCDecrypt(key1, a.salt, a.encVerifierIn)
	if !ok {
		return false
	}
	expected, err := hashBytes(a.hashAlg, verifierIn)
	if err != nil {
		return false
	}
	verifierHash, ok := aesCBCDecrypt(key2, a.salt, a.encVerifierHash)
	if !ok {
		return false
	}
	if len(verifierHash) < len(expected) {
		return false
	}
	return bytes.Equal(expected, verifierHash[:len(expected)])
}

func (a *agileInfo) iteratedHash(password string) ([]byte, error) {
	pass := utf16LE(password)
	salted := append(append([]byte{}, a.salt...), pass...)
	h, err := newHash(a.hashAlg)
	if err != nil {
		return nil, err
	}
	h.Write(salted)
	digest := h.Sum(nil)
	for i := uint32(0); i < a.spinCount; i++ {
		h, _ = newHash(a.hashAlg)
		var ib [4]byte
		binary.LittleEndian.PutUint32(ib[:], i)
		h.Write(ib[:])
		h.Write(digest)
		digest = h.Sum(nil)
	}
	return digest, nil
}

func (a *agileInfo) blockKey(digest, block []byte) ([]byte, error) {
	h, err := newHash(a.hashAlg)
	if err != nil {
		return nil, err
	}
	h.Write(digest)
	h.Write(block)
	sum := h.Sum(nil)
	keyLen := a.keyBits / 8
	if keyLen <= 0 {
		keyLen = 32
	}
	if keyLen > len(sum) {
		keyLen = len(sum)
	}
	return sum[:keyLen], nil
}

func parseAgile(xmlBytes []byte) (*agileInfo, error) {
	// Walk XML for p:encryptedKey / encryptedKey attributes.
	dec := xml.NewDecoder(bytes.NewReader(xmlBytes))
	var a agileInfo
	a.hashAlg = "SHA512"
	a.keyBits = 256
	a.spinCount = 100000
	found := false
	cipherAlg := "AES"

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("XML EncryptionInfo: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			// Also handle self-closing via StartElement only in encoding/xml for empty elements... 
			// encoding/xml emits StartElement+EndElement for empty.
			continue
		}
		local := se.Name.Local
		if local != "encryptedKey" {
			continue
		}
		for _, attr := range se.Attr {
			switch attr.Name.Local {
			case "encryptedVerifierHashInput":
				a.encVerifierIn, err = b64(attr.Value)
			case "encryptedVerifierHashValue":
				a.encVerifierHash, err = b64(attr.Value)
			case "spinCount":
				var n uint32
				fmt.Sscanf(attr.Value, "%d", &n)
				if n > 0 {
					a.spinCount = n
				}
			case "saltValue":
				a.salt, err = b64(attr.Value)
			case "hashAlgorithm":
				a.hashAlg = attr.Value
			case "keyBits":
				fmt.Sscanf(attr.Value, "%d", &a.keyBits)
			case "cipherAlgorithm":
				cipherAlg = attr.Value
			}
			if err != nil {
				return nil, err
			}
		}
		if len(a.salt) > 0 && len(a.encVerifierIn) > 0 && len(a.encVerifierHash) > 0 {
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("не удалось разобрать PasswordKeyEncryptor в EncryptionInfo")
	}
	a.detail = fmt.Sprintf("agile · %s · %s · %d-bit · spin %d", cipherAlg, a.hashAlg, a.keyBits, a.spinCount)
	return &a, nil
}

type standardInfo struct {
	keySize         int
	salt            []byte
	encVerifier     []byte
	encVerifierHash []byte
	detail          string
}

func parseStandard(info []byte) (*standardInfo, error) {
	if len(info) < 12 {
		return nil, fmt.Errorf("Standard EncryptionInfo слишком короткий")
	}
	headerSize := int(binary.LittleEndian.Uint32(info[8:12]))
	if 12+headerSize > len(info) {
		return nil, fmt.Errorf("битый EncryptionHeader")
	}
	header := info[12 : 12+headerSize]
	if len(header) < 20 {
		return nil, fmt.Errorf("EncryptionHeader короткий")
	}
	algID := binary.LittleEndian.Uint32(header[8:12])
	keySize := int(binary.LittleEndian.Uint32(header[16:20]))
	if algID&0xFF00 != 0x6600 {
		return nil, fmt.Errorf("Standard: не AES (algId=0x%X)", algID)
	}
	verifier := info[12+headerSize:]
	if len(verifier) < 72 {
		return nil, fmt.Errorf("EncryptionVerifier короткий")
	}
	saltSize := int(binary.LittleEndian.Uint32(verifier[0:4]))
	if saltSize != 16 {
		return nil, fmt.Errorf("неожиданный saltSize=%d", saltSize)
	}
	s := &standardInfo{
		keySize:         keySize,
		salt:            append([]byte{}, verifier[4:20]...),
		encVerifier:     append([]byte{}, verifier[20:36]...),
		encVerifierHash: append([]byte{}, verifier[40:72]...),
		detail:          fmt.Sprintf("standard · AES · SHA1 · %d-bit", keySize),
	}
	return s, nil
}

func (s *standardInfo) verify(password string) bool {
	key := s.keyFromPassword(password)
	if key == nil {
		return false
	}
	verifier, ok := aesECBDecrypt(key, s.encVerifier)
	if !ok {
		return false
	}
	sum := sha1.Sum(verifier)
	decHash, ok := aesECBDecrypt(key, s.encVerifierHash)
	if !ok || len(decHash) < len(sum) {
		return false
	}
	return bytes.Equal(sum[:], decHash[:len(sum)])
}

func (s *standardInfo) keyFromPassword(password string) []byte {
	pass := utf16LE(password)
	h := sha1.New()
	h.Write(s.salt)
	h.Write(pass)
	digest := h.Sum(nil)
	for i := uint32(0); i < standardSpinCount; i++ {
		h = sha1.New()
		var ib [4]byte
		binary.LittleEndian.PutUint32(ib[:], i)
		h.Write(ib[:])
		h.Write(digest)
		digest = h.Sum(nil)
	}
	h = sha1.New()
	h.Write(digest)
	h.Write([]byte{0, 0, 0, 0})
	digest = h.Sum(nil)

	var buf1 [64]byte
	for i := range buf1 {
		buf1[i] = 0x36
	}
	for i := 0; i < len(digest) && i < 64; i++ {
		buf1[i] ^= digest[i]
	}
	x1 := sha1.Sum(buf1[:])

	var buf2 [64]byte
	for i := range buf2 {
		buf2[i] = 0x5c
	}
	for i := 0; i < len(digest) && i < 64; i++ {
		buf2[i] ^= digest[i]
	}
	x2 := sha1.Sum(buf2[:])

	full := append(x1[:], x2[:]...)
	keyLen := s.keySize / 8
	if keyLen <= 0 || keyLen > len(full) {
		keyLen = len(full)
	}
	return full[:keyLen]
}

func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(out[i*2:], c)
	}
	return out
}

func b64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}

func newHash(alg string) (hash.Hash, error) {
	switch strings.ToUpper(alg) {
	case "SHA512":
		return sha512.New(), nil
	case "SHA1":
		return sha1.New(), nil
	default:
		return nil, fmt.Errorf("hashAlgorithm %s не поддержан", alg)
	}
}

func hashBytes(alg string, data []byte) ([]byte, error) {
	h, err := newHash(alg)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	return h.Sum(nil), nil
}

func aesCBCDecrypt(key, iv, ciphertext []byte) ([]byte, bool) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, false
	}
	if len(iv) < aes.BlockSize {
		return nil, false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	out := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv[:aes.BlockSize])
	mode.CryptBlocks(out, ciphertext)
	return out, true
}

func aesECBDecrypt(key, ciphertext []byte) ([]byte, bool) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	out := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += aes.BlockSize {
		block.Decrypt(out[i:i+aes.BlockSize], ciphertext[i:i+aes.BlockSize])
	}
	return out, true
}
