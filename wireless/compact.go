package wireless

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/cB-Sigma/mbus/records"
)

// Compact M-Bus frames (EN 13757-3:2025 Annex G). A meter may send its
// data records in two halves: a format frame with only the DIF/DIFE and
// VIF/VIFE bytes (identified by a Format Signature, a CRC over them), and
// compact frames with only the data bytes, the Format Signature and a
// Full-Frame-CRC. The receiver keeps the formats per meter and signature,
// rebuilds the full data records from a compact frame and checks them
// against the Full-Frame-CRC (G.1). A full frame can stand in for a
// format frame: its format is derived from it (G.2.2).
//
// Layouts after the TPL header (and, when encrypted, the 2F2F check bytes):
//
//	format frame:  LF, FOS (2), DIF/VIF bytes …        (G.2.4, Table G.5)
//	compact frame: FOS (2), FFC (2), data bytes …       (G.2.3, Table G.4)
//
// LF counts the Format Signature and the format bytes that precede the
// block cipher's idle fillers (G.2.4). FOS and FFC are taken least
// significant byte first, like every other multi-byte M-Bus field; Annex
// G does not state the byte order.

// CI fields of the full, compact and format frames with no, short or long
// TPL header (G.2.1, Table G.2); the full-frame ones are CINoHeader,
// CIShortHeader and CILongHeader.
const (
	CICompactNone  byte = 0x79
	CICompactShort byte = 0x7B
	CICompactLong  byte = 0x73
	CIFormatNone   byte = 0x69
	CIFormatShort  byte = 0x6A
	CIFormatLong   byte = 0x6B
)

// CI fields a partner uses to ask a meter for one frame kind (Table G.1),
// with a long or a short TPL header.
const (
	CIReqFullLong     byte = 0x80
	CIReqCompactLong  byte = 0x84
	CIReqFormatLong   byte = 0x85
	CIReqFullShort    byte = 0x93
	CIReqCompactShort byte = 0x94
	CIReqFormatShort  byte = 0x95
)

// Frame kinds by CI field.
const (
	KindFull    = "full"
	KindCompact = "compact"
	KindFormat  = "format"
)

// FrameKind returns the Annex G frame kind of a CI field ("full",
// "compact" or "format") and its TPL header kind ("none", "short",
// "long"); both are "" for other CI fields.
func FrameKind(ci byte) (kind, header string) {
	switch ci {
	case CINoHeader:
		return KindFull, "none"
	case CIShortHeader:
		return KindFull, "short"
	case CILongHeader:
		return KindFull, "long"
	case CICompactNone:
		return KindCompact, "none"
	case CICompactShort:
		return KindCompact, "short"
	case CICompactLong:
		return KindCompact, "long"
	case CIFormatNone:
		return KindFormat, "none"
	case CIFormatShort:
		return KindFormat, "short"
	case CIFormatLong:
		return KindFormat, "long"
	}
	return "", ""
}

// isCompactCI reports whether a CI field announces a compact or a format
// frame, whose application data is not data records.
func isCompactCI(ci byte) bool {
	k, _ := FrameKind(ci)
	return k == KindCompact || k == KindFormat
}

// Errors of the compact frame handling.
var (
	// ErrCompactFrame is what Decode returns for a compact or format frame:
	// its records need the format cache (FormatCache.Complete).
	ErrCompactFrame = errors.New("compact or format frame: the data records need the meter's format")
	// ErrFormatUnknown: no format with the compact frame's signature is
	// known for the meter yet.
	ErrFormatUnknown = errors.New("compact frame whose format (signature) is not known yet")
	// ErrFullFrameCRC: the rebuilt frame does not match the Full-Frame-CRC;
	// the cached format is outdated and is dropped.
	ErrFullFrameCRC = errors.New("the rebuilt full frame does not match its Full-Frame-CRC")
	// ErrFormatSignature: a format frame's bytes do not match its signature.
	ErrFormatSignature = errors.New("the format frame does not match its Format Signature")
)

// FormatSignature is the Format Signature of a format: the EN 13757 CRC
// (polynomial 3D65h, initial value 0, complemented) over the DIF/DIFE and
// VIF/VIFE bytes from the first DIF to the last VIF or DIF (G.4).
func FormatSignature(format []byte) uint16 { return CRC(format) }

// FullFrameCRC is the Full-Frame-CRC of a full frame's application data:
// the same CRC over the data records from the first byte to the end of
// the last record (G.3). records excludes the TPL header and the AES check
// bytes; trailing idle fillers are not part of it and are ignored.
func FullFrameCRC(records []byte) uint16 { return CRC(records[:recordsEnd(records)]) }

// recordsEnd is where the last data record (not an idle filler) ends; on
// a malformed record it is the length.
func recordsEnd(p []byte) int {
	last := 0
	for i := 0; i < len(p); {
		filler := p[i] == 0x2F
		end, err := skipRecord(p, i)
		if err != nil {
			return len(p)
		}
		i = end
		if !filler {
			last = i
		}
	}
	return last
}

// skipRecord returns where the data record at p[i:] ends.
func skipRecord(p []byte, i int) (int, error) {
	end, n, err := recordHeader(p, i)
	if err != nil {
		return 0, err
	}
	i = end
	switch {
	case n == nRest:
		return len(p), nil
	case n == nLVAR:
		if i >= len(p) {
			return 0, errors.New("data ends before LVAR")
		}
		l := records.LVARLength(int(p[i]))
		if l < 0 {
			return 0, fmt.Errorf("LVAR 0x%02X", p[i])
		}
		i += 1 + l
	default:
		i += n
	}
	if i > len(p) {
		return 0, errors.New("a data field runs past the end")
	}
	return i, nil
}

// fmtEntry is one data record of a format: its DIF … VIF bytes and how
// long its data is (n bytes; -1 LVAR; -3 to the end; 0 none).
type fmtEntry struct {
	hdr    []byte
	n      int
	filler bool
}

const (
	nLVAR = -1
	nRest = -3
)

// recordHeader reads the DIF, DIFEs, VIF, VIFEs (and a plain-text VIF's
// text) at p[i:], returning where they end and the data length code.
func recordHeader(p []byte, i int) (end, n int, err error) {
	dif := p[i]
	i++
	switch dif {
	case 0x2F, 0x7F:
		return i, 0, nil
	case 0x0F, 0x1F:
		return i, nRest, nil
	}
	if dif&0x0F == 0x0F {
		return 0, 0, fmt.Errorf("special DIF 0x%02X", dif)
	}
	for ext := dif&0x80 != 0; ext; {
		if i >= len(p) {
			return 0, 0, errors.New("the format ends inside the DIFEs")
		}
		ext = p[i]&0x80 != 0
		i++
	}
	if i >= len(p) {
		return 0, 0, errors.New("the format ends before the VIF")
	}
	vif := p[i]
	i++
	for ext := vif&0x80 != 0; ext; {
		if i >= len(p) {
			return 0, 0, errors.New("the format ends inside the VIFEs")
		}
		ext = p[i]&0x80 != 0
		i++
	}
	if vif&0x7F == 0x7C { // plain-text unit: length and text belong to the format
		if i >= len(p) || i+1+int(p[i]) > len(p) {
			return 0, 0, errors.New("plain-text VIF runs past the end")
		}
		i += 1 + int(p[i])
	}
	n = records.DataLength(dif)
	if n == -1 {
		n = nLVAR
	}
	return i, n, nil
}

// parseFormat splits a format into its records.
func parseFormat(format []byte) ([]fmtEntry, error) {
	var out []fmtEntry
	for i := 0; i < len(format); {
		end, n, err := recordHeader(format, i)
		if err != nil {
			return nil, fmt.Errorf("format record %d: %w", len(out), err)
		}
		out = append(out, fmtEntry{hdr: format[i:end], n: n, filler: format[i] == 0x2F})
		i = end
		if n == nRest && i != len(format) {
			return nil, errors.New("format: manufacturer data (DIF 0F/1F) is not last")
		}
	}
	return out, nil
}

// BuildFormat derives the format (the DIF … VIF bytes, idle fillers
// included) from a full frame's data records (G.2.2). Trailing idle
// fillers are left out.
func BuildFormat(records []byte) ([]byte, error) {
	p := records[:recordsEnd(records)]
	var f []byte
	for i := 0; i < len(p); {
		hdrEnd, _, err := recordHeader(p, i)
		if err != nil {
			return nil, err
		}
		end, err := skipRecord(p, i)
		if err != nil {
			return nil, err
		}
		f = append(f, p[i:hdrEnd]...)
		i = end
	}
	return f, nil
}

// rebuild interleaves a format with a compact frame's data. encEnd is
// where the encrypted part of data ends when the frame is partly
// encrypted (-1 otherwise): block cipher fillers there are skipped. With
// eatFill, an idle-filler DIF of the format consumes a 2F byte of the
// data (the fillers of a partly encrypted full frame reappear in its
// compact frame, G.5.4).
func rebuild(entries []fmtEntry, data []byte, encEnd int, eatFill bool) ([]byte, error) {
	var out []byte
	pos := 0
	for k, e := range entries {
		if e.filler {
			out = append(out, 0x2F)
			if eatFill && pos < len(data) && data[pos] == 0x2F && (encEnd < 0 || pos < encEnd) {
				pos++
			}
			continue
		}
		out = append(out, e.hdr...)
		if e.n != 0 && encEnd >= 0 && pos < encEnd && allFill(data[pos:encEnd]) {
			pos = encEnd
		}
		n := e.n
		switch n {
		case nRest:
			out = append(out, data[pos:]...)
			pos = len(data)
			continue
		case nLVAR:
			if pos >= len(data) {
				return nil, fmt.Errorf("record %d: the compact data ends before LVAR", k)
			}
			l := records.LVARLength(int(data[pos]))
			if l < 0 {
				return nil, fmt.Errorf("record %d: LVAR 0x%02X", k, data[pos])
			}
			n = 1 + l
		}
		if pos+n > len(data) {
			return nil, fmt.Errorf("record %d: the compact data is shorter than its format", k)
		}
		out = append(out, data[pos:pos+n]...)
		pos += n
	}
	if !allFill(data[pos:]) {
		return nil, fmt.Errorf("the compact data has %d bytes more than its format", len(data)-pos)
	}
	return out, nil
}

func allFill(b []byte) bool {
	for _, x := range b {
		if x != 0x2F {
			return false
		}
	}
	return true
}

// Rebuild turns a compact frame's data into the full frame's data records
// with a format and checks the Full-Frame-CRC. encEnd is where the
// encrypted part of data ends in a partly encrypted frame, else -1.
func Rebuild(format, data []byte, ffc uint16, encEnd int) ([]byte, error) {
	entries, err := parseFormat(format)
	if err != nil {
		return nil, err
	}
	var firstErr error
	for _, eat := range []bool{true, false} {
		full, err := rebuild(entries, data, encEnd, eat)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if FullFrameCRC(full) == ffc {
			return full, nil
		}
		if firstErr == nil {
			firstErr = ErrFullFrameCRC
		}
	}
	if !errors.Is(firstErr, ErrFullFrameCRC) {
		firstErr = fmt.Errorf("%w (%v)", ErrFullFrameCRC, firstErr)
	}
	return nil, firstErr
}

// ---- cache ----------------------------------------------------------------

// DefaultFormatCacheSize bounds the formats kept (and persisted).
const DefaultFormatCacheSize = 1024

// FormatCache keeps the formats of meters by meter key and Format
// Signature, the least recently used dropped beyond its size. It is safe
// for concurrent use. The wireless driver persists it (SavedFormat); the
// wired M-Bus IPE may use one in memory.
type FormatCache struct {
	// IgnoreFullFrameCRC rebuilds a compact frame whose rebuilt records
	// fail the Full-Frame-CRC anyway (as wmbusmeters does, which does not
	// check it), and keeps the format. Off by default: the CRC is what
	// tells an outdated format from the right one. A frame let through
	// this way carries a warning (CompactInfo.Warning, Telegram.Warnings).
	IgnoreFullFrameCRC bool

	mu      sync.Mutex
	max     int
	seq     uint64
	formats map[string]*cachedFormat // meter "/" signature
	compact map[string]bool          // meters that sent a compact or format frame
	dirty   bool
}

type cachedFormat struct {
	meter  string
	sig    uint16
	format []byte
	used   uint64
}

// SavedFormat is a persisted format.
type SavedFormat struct {
	Meter     string `json:"meter"`
	Signature uint16 `json:"signature"`
	Format    string `json:"format"` // hex
}

// NewFormatCache returns a cache of at most max formats (0: the default).
func NewFormatCache(max int) *FormatCache {
	if max <= 0 {
		max = DefaultFormatCacheSize
	}
	return &FormatCache{max: max, formats: map[string]*cachedFormat{}, compact: map[string]bool{}}
}

func cacheKey(meter string, sig uint16) string { return fmt.Sprintf("%s/%04X", meter, sig) }

// Put stores a format for a meter and returns its signature.
func (c *FormatCache) Put(meter string, format []byte) uint16 {
	sig := FormatSignature(format)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.put(meter, sig, format)
	return sig
}

func (c *FormatCache) put(meter string, sig uint16, format []byte) {
	c.seq++
	k := cacheKey(meter, sig)
	if f, ok := c.formats[k]; ok {
		f.used = c.seq
		return
	}
	c.formats[k] = &cachedFormat{meter: meter, sig: sig, format: append([]byte(nil), format...), used: c.seq}
	c.dirty = true
	for len(c.formats) > c.max {
		var oldK string
		var old uint64
		for k, f := range c.formats {
			if oldK == "" || f.used < old {
				oldK, old = k, f.used
			}
		}
		delete(c.formats, oldK)
	}
}

// Get returns a meter's format with a signature.
func (c *FormatCache) Get(meter string, sig uint16) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, ok := c.formats[cacheKey(meter, sig)]
	if !ok {
		return nil, false
	}
	c.seq++
	f.used = c.seq
	return f.format, true
}

// Forget drops a format (outdated: its Full-Frame-CRC failed).
func (c *FormatCache) Forget(meter string, sig uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := cacheKey(meter, sig)
	if _, ok := c.formats[k]; ok {
		delete(c.formats, k)
		c.dirty = true
	}
}

// Len is the number of formats kept.
func (c *FormatCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.formats)
}

// Snapshot returns the formats to persist and clears the changed flag;
// changed reports whether anything changed since the last snapshot (when
// nothing did, saved is nil).
func (c *FormatCache) Snapshot() (saved []SavedFormat, changed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dirty {
		return nil, false
	}
	for _, f := range c.formats {
		saved = append(saved, SavedFormat{Meter: f.meter, Signature: f.sig, Format: strings.ToUpper(hex.EncodeToString(f.format))})
	}
	sort.Slice(saved, func(i, j int) bool {
		if saved[i].Meter != saved[j].Meter {
			return saved[i].Meter < saved[j].Meter
		}
		return saved[i].Signature < saved[j].Signature
	})
	changed, c.dirty = c.dirty, false
	return saved, changed
}

// Restore adds persisted formats; entries whose bytes do not match their
// signature are skipped.
func (c *FormatCache) Restore(saved []SavedFormat) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range saved {
		f, err := hex.DecodeString(s.Format)
		if err != nil || FormatSignature(f) != s.Signature || s.Meter == "" {
			continue
		}
		c.put(s.Meter, s.Signature, f)
		c.compact[s.Meter] = true
	}
	c.dirty = false
}

// Expand handles the application data of an unencrypted frame (after the
// TPL header) by its CI field: a format frame's format is stored (full is
// nil); a compact frame is rebuilt into full data records and checked; a
// full frame's format is learnt and its data returned. sig is the Format
// Signature.
func (c *FormatCache) Expand(meterKey string, ci byte, apl []byte) (full []byte, sig uint16, err error) {
	return c.expand(meterKey, ci, apl, false, -1)
}

// ExpandEncrypted is Expand for decrypted data that starts with the two
// AES check bytes (2F2F); encLen is how many bytes of apl were encrypted
// (the rest was sent in the clear).
func (c *FormatCache) ExpandEncrypted(meterKey string, ci byte, apl []byte, encLen int) (full []byte, sig uint16, err error) {
	return c.expand(meterKey, ci, apl, true, encLen)
}

func (c *FormatCache) expand(meter string, ci byte, apl []byte, enc bool, encLen int) ([]byte, uint16, error) {
	off := 0
	if enc {
		if len(apl) < 2 {
			return nil, 0, errTruncated
		}
		off = 2
	}
	partial := enc && encLen > 0 && encLen < len(apl)
	kind, _ := FrameKind(ci)
	switch kind {
	case KindFull:
		recs := apl[off:]
		f, err := BuildFormat(recs)
		if err != nil {
			return recs, 0, nil // not ours to judge: the record parser reports it
		}
		sig := FormatSignature(f)
		c.mu.Lock()
		if c.compact[meter] {
			c.put(meter, sig, f)
		}
		c.mu.Unlock()
		return recs, sig, nil
	case KindFormat:
		if len(apl) < off+3 {
			return nil, 0, errTruncated
		}
		lf := int(apl[off])
		sig := uint16(apl[off+1]) | uint16(apl[off+2])<<8
		body := off + 3
		var head, tail []byte
		switch {
		case partial:
			end := encLen
			if lf >= 2 && off+1+lf <= encLen {
				end = off + 1 + lf
			}
			head, tail = apl[body:end], apl[encLen:]
		case lf >= 2 && off+1+lf <= len(apl):
			head = apl[body : off+1+lf]
		default:
			head = apl[body:]
		}
		// Without a usable LF the cipher's fillers and filler DIFs look
		// alike: the signature decides how many trailing 2F belong.
		for {
			f := append(append([]byte(nil), head...), tail...)
			if FormatSignature(f) == sig {
				c.mu.Lock()
				c.compact[meter] = true
				c.put(meter, sig, f)
				c.mu.Unlock()
				return nil, sig, nil
			}
			if len(head) == 0 || head[len(head)-1] != 0x2F {
				return nil, sig, ErrFormatSignature
			}
			head = head[:len(head)-1]
		}
	case KindCompact:
		if len(apl) < off+4 {
			return nil, 0, errTruncated
		}
		sig := uint16(apl[off]) | uint16(apl[off+1])<<8
		ffc := uint16(apl[off+2]) | uint16(apl[off+3])<<8
		data := apl[off+4:]
		encEnd := -1
		if partial {
			encEnd = max(encLen-off-4, 0)
		}
		c.mu.Lock()
		if !c.compact[meter] {
			c.compact[meter] = true
			c.dirty = true
		}
		c.mu.Unlock()
		f, ok := c.Get(meter, sig)
		if !ok {
			return nil, sig, ErrFormatUnknown
		}
		full, err := Rebuild(f, data, ffc, encEnd)
		if errors.Is(err, ErrFullFrameCRC) && c.IgnoreFullFrameCRC {
			if lenient, lerr := rebuildAny(f, data, encEnd); lerr == nil {
				return lenient, sig, ErrFullFrameCRCIgnored
			}
		}
		if err != nil {
			c.Forget(meter, sig)
			return nil, sig, err
		}
		return full, sig, nil
	}
	return nil, 0, fmt.Errorf("%w: CI field 0x%02X is not a full, compact or format frame", ErrUnsupport, ci)
}

// CompactInfo describes how a telegram's records were obtained.
type CompactInfo struct {
	Kind      string // "full", "compact" or "format"
	Signature uint16
	Known     bool // a compact frame's format was known
	// Warning is set when a frame was let through by a lenient option
	// (FormatCache.IgnoreFullFrameCRC).
	Warning string
}

// Complete finishes a telegram that Decode left with ErrCompactFrame (or
// learns the format of a full frame when decodeErr is nil). It returns
// the telegram's error after that: nil when its records were rebuilt.
func (c *FormatCache) Complete(tg *Telegram, decodeErr error) (CompactInfo, error) {
	kind, _ := FrameKind(tg.CI)
	info := CompactInfo{Kind: kind}
	if kind == "" || (decodeErr != nil && !errors.Is(decodeErr, ErrCompactFrame)) {
		return info, decodeErr
	}
	// TPL security modes 5 and 7 leave the two AES check bytes in front.
	check := tg.Encrypted && (tg.Mode == 5 || tg.Mode == 7)
	if kind == KindFull {
		_, info.Signature, _ = c.expand(tg.Meter.Key(), tg.CI, tg.APL, check, -1)
		return info, decodeErr
	}
	encLen := -1
	if check {
		if n, err := tg.encLen(tg.APL); err == nil {
			encLen = n
		}
	}
	full, sig, err := c.expand(tg.Meter.Key(), tg.CI, tg.APL, check, encLen)
	info.Signature = sig
	if err == ErrFullFrameCRCIgnored {
		info.Warning = WarnFullFrameCRC
		tg.Warnings = append(tg.Warnings, WarnFullFrameCRC)
		err = nil
	}
	if err != nil {
		return info, err
	}
	if kind == KindFormat {
		return info, nil
	}
	info.Known = true
	tg.APL = full
	tg.Records, err = records.ParseRecords(full)
	return info, err
}

// WarnFullFrameCRC is the warning of a compact frame rebuilt although its
// Full-Frame-CRC did not match (FormatCache.IgnoreFullFrameCRC).
const WarnFullFrameCRC = "full-frame-crc-ignored: the rebuilt records do not match the compact frame's Full-Frame-CRC; the format may be outdated"

// ErrFullFrameCRCIgnored comes with the rebuilt records from Expand and
// ExpandEncrypted when FormatCache.IgnoreFullFrameCRC let a frame through
// whose Full-Frame-CRC did not match: the records are returned, and the
// error is the warning. (Complete turns it into Warnings.)
var ErrFullFrameCRCIgnored = errors.New(WarnFullFrameCRC)

// rebuildAny rebuilds without the Full-Frame-CRC check.
func rebuildAny(format, data []byte, encEnd int) ([]byte, error) {
	entries, err := parseFormat(format)
	if err != nil {
		return nil, err
	}
	var firstErr error
	for _, eat := range []bool{true, false} {
		full, err := rebuild(entries, data, encEnd, eat)
		if err == nil {
			return full, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}
