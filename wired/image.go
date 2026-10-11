package wired

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Image transfer (EN 13757-3:2025 clause 15 and annex I): a head end
// sends an image (firmware, tables) to a device in blocks. Commands and
// responses are segments (segment length, segment ID, function, sub-
// function, parameters) after an image transfer CI field.

// Image transfer CI fields (table I.1).
const (
	CIImageCmdLong  = 0xC0 // command to the device, long header
	CIImageRspShort = 0xC1 // response from the device, short header
	CIImageRspLong  = 0xC2 // response from the device, long header
	CIImageCmdShort = 0xC7 // command to the device, short header
)

// Image transfer functions (table I.4); a response has bit 7 set.
const (
	ImgPrepare      = 0x00
	ImgSynchronize  = 0x01
	ImgTransfer     = 0x02
	ImgCompletion   = 0x03
	ImgState        = 0x04
	ImgValidate     = 0x05
	ImgActivate     = 0x06
	ImgTerminate    = 0x07
	ImgActiveImages = 0x08
	ImgResponse     = 0x80
)

// Sub-function bits.
const (
	// Prepare command (table I.6).
	PrepMAC  = 0x01
	PrepADT  = 0x02
	PrepSZIN = 0x04
	PrepIDEN = 0x08
	PrepMCAS = 0x10
	PrepINFO = 0x20
	// Prepare response (table I.13).
	PrepRspAINF = 0x01
	PrepRspSZIN = 0x02
	PrepRspRDY  = 0x04 // set: not ready
	PrepRspIDEN = 0x08
	PrepRspMCAS = 0x10
	PrepRspINFO = 0x20
	// Synchronize command (table I.16).
	SyncCTDN = 0x01
	SyncIDEN = 0x02
	// Transfer command (table I.18): SEQ in bits 1-2.
	XferAINF         = 0x01
	XferSeqFirst     = 0x02
	XferSeqMiddle    = 0x04
	XferSeqLast      = 0x06
	XferIDEN         = 0x08
	XferREM          = 0x10
	rspIDEN          = 0x10 // transfer, state, validate, activate, terminate responses: IDEN in bit 4, state in bits 0-3
	CmplIDEN         = 0x02 // completion, state, validate commands (tables I.22, I.26, I.31)
	CmplAINF         = 0x01
	CmplRspNBR       = 0x01 // completion response (table I.24)
	CmplRspLIB       = 0x02
	CmplRspTNLB      = 0x04
	CmplRspIDEN      = 0x08
	ActADT           = 0x01 // activate command (table I.35)
	ActIDEN          = 0x02
	TermTIT          = 0x01 // terminate command (table I.39)
	TermTTR          = 0x02
	TermIDEN         = 0x04
	ActiveImagesLAI  = 0x01 // active images response (table I.45)
	lostBlocksFollow = 0xFFFF
)

// Transfer states (table I.29).
var ImageStates = [16]string{"sync_activated", "sync_terminated", "transfer_initiated", "transfer_active",
	"transfer_terminated", "transfer_successful", "transfer_failed", "validation_initiated", "validation_active",
	"validation_successful", "validation_failed", "activation_initiated", "activation_successful",
	"activation_failed", "image_transfer_terminated", "idle"}

// Image transfer states used by the head end.
const (
	StateTransferSuccessful   = 5
	StateTransferFailed       = 6
	StateValidationInitiated  = 7
	StateValidationActive     = 8
	StateValidationSuccessful = 9
	StateValidationFailed     = 10
	StateActivationInitiated  = 11
	StateActivationSuccessful = 12
	StateActivationFailed     = 13
	StateIdle                 = 15
)

// PrepareResults names the preparation results (table I.14).
var PrepareResults = []string{"accepted", "version_not_accepted", "minimum_sw_version", "minimum_hw_version",
	"update_disabled", "image_type_not_supported", "image_too_big", "other_error"}

// ImageID is the 8-byte image identifier field (table I.7).
type ImageID struct {
	Manufacturer uint16
	Version      byte
	DeviceType   byte
	Image        uint32 // manufacturer image identifier
}

// Bytes is the field as sent (manufacturer and image number LSB first).
func (id ImageID) Bytes() []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint16(b, id.Manufacturer)
	b[2], b[3] = id.Version, id.DeviceType
	binary.LittleEndian.PutUint32(b[4:], id.Image)
	return b
}

func parseImageID(b []byte) ImageID {
	return ImageID{Manufacturer: binary.LittleEndian.Uint16(b), Version: b[2], DeviceType: b[3], Image: binary.LittleEndian.Uint32(b[4:])}
}

// Segment is one command or response segment (tables I.2 and I.3).
type Segment struct {
	ID       byte
	Function byte
	Sub      byte
	Params   []byte
}

// ErrSegmentLength is a segment length below 3 or past the data: the
// whole structure is ignored (annex I.2.2).
var ErrSegmentLength = errors.New("invalid image transfer segment length")

// EncodeSegments concatenates segments: a 2-byte length (LSB first)
// counting the segment ID, function, sub-function and parameters.
func EncodeSegments(segs ...Segment) []byte {
	var out []byte
	for _, s := range segs {
		n := 3 + len(s.Params)
		out = append(out, byte(n), byte(n>>8), s.ID, s.Function, s.Sub)
		out = append(out, s.Params...)
	}
	return out
}

// ParseSegments splits image transfer data into segments. Any invalid
// length rejects the whole structure.
func ParseSegments(b []byte) ([]Segment, error) {
	var out []Segment
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, ErrSegmentLength
		}
		n := int(binary.LittleEndian.Uint16(b))
		if n < 3 || 2+n > len(b) {
			return nil, ErrSegmentLength
		}
		s := b[2 : 2+n]
		out = append(out, Segment{ID: s[0], Function: s[1], Sub: s[2], Params: append([]byte(nil), s[3:]...)})
		b = b[2+n:]
	}
	return out, nil
}

// MAC is the MAC field of a prepare command (table I.9): algorithm (01h
// HMAC-SHA256/8, 02h HMAC-SHA256/16, 03h CMAC/8, 04h CMAC, 05h GMAC/12),
// key ID and version, and the value MSB first, padded with zeros to 16
// bytes.
type MAC struct {
	Algorithm  byte
	KeyID      byte
	KeyVersion byte
	Value      []byte
}

// PrepareCmd is the prepare command (tables I.5 and I.6). The optional
// fields are present when set.
type PrepareCmd struct {
	Multicast  bool
	Absolute   bool   // ADT: Start is EPOCH 2013 seconds, else seconds from now
	Start      uint32 // with Multicast
	Pace       byte   // seconds between blocks, with Multicast
	Size       *SizeInfo
	ID         *ImageID
	MAC        *MAC
	Additional *[2]byte
}

// SizeInfo is the size information field (table I.8).
type SizeInfo struct {
	Blocks     uint16
	BlockSize  uint16
	Repetition byte
}

func (s SizeInfo) bytes() []byte {
	b := make([]byte, 5)
	binary.LittleEndian.PutUint16(b, s.Blocks)
	binary.LittleEndian.PutUint16(b[2:], s.BlockSize)
	b[4] = s.Repetition
	return b
}

// Segment encodes the command; fields follow the sub-function in the
// order of table I.5.
func (c PrepareCmd) Segment(id byte) (Segment, error) {
	var sub byte
	var p []byte
	if c.Multicast {
		sub |= PrepMCAS
		if c.Absolute {
			sub |= PrepADT
		}
		p = binary.LittleEndian.AppendUint32(p, c.Start)
		p = append(p, c.Pace)
	}
	if c.Size != nil {
		sub |= PrepSZIN
		p = append(p, c.Size.bytes()...)
	}
	if c.ID != nil {
		sub |= PrepIDEN
		p = append(p, c.ID.Bytes()...)
	}
	if c.MAC != nil {
		if len(c.MAC.Value) > 16 {
			return Segment{}, errors.New("a MAC value has at most 16 bytes")
		}
		sub |= PrepMAC
		v := make([]byte, 16)
		copy(v, c.MAC.Value)
		p = append(p, c.MAC.Algorithm, c.MAC.KeyID, c.MAC.KeyVersion)
		p = append(p, v...)
	}
	if c.Additional != nil {
		sub |= PrepINFO
		p = append(p, c.Additional[:]...)
	}
	return Segment{ID: id, Function: ImgPrepare, Sub: sub, Params: p}, nil
}

// PrepareRsp is the prepare response (tables I.12 to I.14).
type PrepareRsp struct {
	Ready      bool
	Multicast  bool
	Result     byte
	ID         *ImageID
	Size       *SizeInfo
	Additional []byte
}

// ParsePrepareRsp decodes a prepare response segment.
func ParsePrepareRsp(s Segment) (PrepareRsp, error) {
	if s.Function != ImgPrepare|ImgResponse {
		return PrepareRsp{}, fmt.Errorf("function %02Xh is not a prepare response", s.Function)
	}
	p := s.Params
	if len(p) < 1 {
		return PrepareRsp{}, errors.New("the prepare response has no preparation result")
	}
	r := PrepareRsp{Ready: s.Sub&PrepRspRDY == 0, Multicast: s.Sub&PrepRspMCAS != 0, Result: p[0]}
	p = p[1:]
	if s.Sub&PrepRspIDEN != 0 {
		if len(p) < 8 {
			return r, errors.New("the prepare response's image identifier is short")
		}
		id := parseImageID(p)
		r.ID, p = &id, p[8:]
	}
	if s.Sub&PrepRspSZIN != 0 {
		if len(p) < 5 {
			return r, errors.New("the prepare response's size information is short")
		}
		r.Size = &SizeInfo{Blocks: binary.LittleEndian.Uint16(p), BlockSize: binary.LittleEndian.Uint16(p[2:]), Repetition: p[4]}
		p = p[5:]
	}
	if s.Sub&(PrepRspAINF|PrepRspINFO) != 0 && len(p) >= 2 {
		r.Additional = p[:2]
	}
	return r, nil
}

// ResultName names a preparation result.
func (r PrepareRsp) ResultName() string {
	if int(r.Result) < len(PrepareResults) {
		return PrepareResults[r.Result]
	}
	return "reserved"
}

// TransferCmd is one image block (tables I.17 and I.18).
type TransferCmd struct {
	ID        *ImageID
	Block     uint16
	Blocks    uint16 // total, for the sequence state and remaining field
	Remaining bool   // include the remaining field
	Data      []byte
}

// Segment encodes the command.
func (c TransferCmd) Segment(id byte) Segment {
	var sub byte
	switch {
	case c.Blocks == 1 || c.Block+1 == c.Blocks:
		sub = XferSeqLast
	case c.Block == 0:
		sub = XferSeqFirst
	default:
		sub = XferSeqMiddle
	}
	var p []byte
	if c.ID != nil {
		sub |= XferIDEN
		p = append(p, c.ID.Bytes()...)
	}
	p = binary.LittleEndian.AppendUint16(p, c.Block)
	if c.Remaining {
		sub |= XferREM
		p = binary.LittleEndian.AppendUint16(p, c.Blocks-1-c.Block)
	}
	p = append(p, c.Data...)
	return Segment{ID: id, Function: ImgTransfer, Sub: sub, Params: p}
}

// ParseTransferCmd decodes a transfer command segment (used by
// simulators).
func ParseTransferCmd(s Segment) (TransferCmd, error) {
	p := s.Params
	var c TransferCmd
	if s.Sub&XferIDEN != 0 {
		if len(p) < 8 {
			return c, errors.New("short image identifier")
		}
		id := parseImageID(p)
		c.ID, p = &id, p[8:]
	}
	if len(p) < 2 {
		return c, errors.New("no block number")
	}
	c.Block, p = binary.LittleEndian.Uint16(p), p[2:]
	if s.Sub&XferREM != 0 {
		if len(p) < 2 {
			return c, errors.New("short remaining field")
		}
		c.Remaining, p = true, p[2:]
	}
	if s.Sub&XferAINF != 0 {
		if len(p) < 2 {
			return c, errors.New("short additional information")
		}
		p = p[2:]
	}
	c.Data = p
	return c, nil
}

// SimpleCmd is a command whose parameters are an optional image
// identifier and optional fields in order: completion, state and
// validate (IDEN bit 1), terminate (IDEN bit 2 with T_TR/T_IT flags) and
// activate (IDEN bit 1 and a 4-byte date and time).
func SimpleCmd(id byte, function byte, img *ImageID, flags byte, extra []byte) Segment {
	sub := flags
	var p []byte
	if img != nil {
		switch function {
		case ImgTerminate:
			sub |= TermIDEN
		default:
			sub |= CmplIDEN
		}
		p = append(p, img.Bytes()...)
	}
	p = append(p, extra...)
	return Segment{ID: id, Function: function, Sub: sub, Params: p}
}

// StateRsp is a response carrying the transfer state in the sub-function
// (transfer, state, validate, activate and terminate responses).
type StateRsp struct {
	Function byte
	State    int
	ID       *ImageID
}

// ParseStateRsp decodes such a response.
func ParseStateRsp(s Segment) (StateRsp, error) {
	switch s.Function {
	case ImgTransfer | ImgResponse, ImgState | ImgResponse, ImgValidate | ImgResponse, ImgActivate | ImgResponse, ImgTerminate | ImgResponse:
	default:
		return StateRsp{}, fmt.Errorf("function %02Xh carries no transfer state", s.Function)
	}
	r := StateRsp{Function: s.Function &^ ImgResponse, State: int(s.Sub & 0x0F)}
	if s.Sub&rspIDEN != 0 && len(s.Params) >= 8 {
		id := parseImageID(s.Params)
		r.ID = &id
	}
	return r, nil
}

// CompletionRsp is the completion response (tables I.23 and I.24).
type CompletionRsp struct {
	NoneReceived bool
	Lost         []uint16 // missing blocks
	LostFrom     int      // -1, or the first block of a missing tail (FFFFh marker)
	Total        int      // total number of lost blocks, -1 when not given
	ID           *ImageID
}

// ParseCompletionRsp decodes a completion response.
func ParseCompletionRsp(s Segment) (CompletionRsp, error) {
	if s.Function != ImgCompletion|ImgResponse {
		return CompletionRsp{}, fmt.Errorf("function %02Xh is not a completion response", s.Function)
	}
	r := CompletionRsp{NoneReceived: s.Sub&CmplRspNBR != 0, LostFrom: -1, Total: -1}
	p := s.Params
	if s.Sub&CmplRspIDEN != 0 {
		if len(p) < 8 {
			return r, errors.New("short image identifier")
		}
		id := parseImageID(p)
		r.ID, p = &id, p[8:]
	}
	if s.Sub&CmplRspTNLB != 0 {
		if len(p) < 2 {
			return r, errors.New("short total number of lost blocks")
		}
		r.Total, p = int(binary.LittleEndian.Uint16(p)), p[2:]
	}
	if s.Sub&CmplRspLIB != 0 {
		prev := -1
		for len(p) >= 2 {
			v := binary.LittleEndian.Uint16(p)
			p = p[2:]
			if v == lostBlocksFollow {
				// Every block after the previous element is missing (all of
				// them when FFFFh comes first).
				r.LostFrom = prev + 1
				break
			}
			r.Lost = append(r.Lost, v)
			prev = int(v)
		}
	}
	return r, nil
}

// Missing lists the blocks to send again, of n in the image.
func (r CompletionRsp) Missing(n int) []uint16 {
	if r.NoneReceived {
		r.LostFrom = 0
	}
	out := append([]uint16(nil), r.Lost...)
	if r.LostFrom >= 0 {
		for b := r.LostFrom; b < n; b++ {
			out = append(out, uint16(b))
		}
	}
	return out
}

// EncodeCompletionRsp builds a completion response (for simulators).
func EncodeCompletionRsp(id byte, lost []uint16, none bool) Segment {
	var sub byte
	var p []byte
	if none {
		sub |= CmplRspNBR | CmplRspLIB
		p = binary.LittleEndian.AppendUint16(p, lostBlocksFollow)
	} else if len(lost) > 0 {
		sub |= CmplRspLIB | CmplRspTNLB
		p = binary.LittleEndian.AppendUint16(p, uint16(len(lost)))
		for _, b := range lost {
			p = binary.LittleEndian.AppendUint16(p, b)
		}
	}
	return Segment{ID: id, Function: ImgCompletion | ImgResponse, Sub: sub, Params: p}
}
