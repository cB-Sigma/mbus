package mbal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// A minimal CBOR (RFC 8949) reader and writer for the CIoT payload of
// Annex C.4.3: integers, byte and text strings (also indefinite length),
// arrays and maps (also indefinite length), tags, simple values and floats.
// Decoded values are uint64, int64, []byte, string, []any, map[any]any
// (keys uint64, int64 or string), cborTag, bool, nil and float64.

type cborTag struct {
	Num uint64
	Val any
}

var errCBOR = errors.New("malformed CBOR")

const cborMaxDepth = 16

type cborReader struct {
	b []byte
	i int
}

func cborDecode(b []byte) (any, error) {
	r := &cborReader{b: b}
	v, err := r.value(0)
	if err != nil {
		return nil, err
	}
	if r.i != len(b) {
		return nil, fmt.Errorf("%w: %d bytes after the item", errCBOR, len(b)-r.i)
	}
	return v, nil
}

var cborBreak = &struct{}{}

func (r *cborReader) head() (major byte, info byte, arg uint64, err error) {
	if r.i >= len(r.b) {
		return 0, 0, 0, fmt.Errorf("%w: truncated", errCBOR)
	}
	c := r.b[r.i]
	r.i++
	major, info = c>>5, c&0x1F
	switch {
	case info < 24:
		arg = uint64(info)
	case info <= 27:
		n := 1 << (info - 24)
		if r.i+n > len(r.b) {
			return 0, 0, 0, fmt.Errorf("%w: truncated", errCBOR)
		}
		for _, x := range r.b[r.i : r.i+n] {
			arg = arg<<8 | uint64(x)
		}
		r.i += n
	case info == 31:
		if major == 0 || major == 1 || major == 6 {
			return 0, 0, 0, fmt.Errorf("%w: indefinite length on major type %d", errCBOR, major)
		}
	default:
		return 0, 0, 0, fmt.Errorf("%w: reserved additional information %d", errCBOR, info)
	}
	return major, info, arg, nil
}

func (r *cborReader) value(depth int) (any, error) {
	if depth > cborMaxDepth {
		return nil, fmt.Errorf("%w: nested too deeply", errCBOR)
	}
	major, info, arg, err := r.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		return arg, nil
	case 1:
		if arg > math.MaxInt64 {
			return nil, fmt.Errorf("%w: negative integer out of range", errCBOR)
		}
		return -1 - int64(arg), nil
	case 2, 3:
		var s []byte
		if info == 31 {
			for {
				v, err := r.value(depth + 1)
				if err != nil {
					return nil, err
				}
				if v == cborBreak {
					break
				}
				switch c := v.(type) {
				case []byte:
					if major != 2 {
						return nil, fmt.Errorf("%w: chunk type", errCBOR)
					}
					s = append(s, c...)
				case string:
					if major != 3 {
						return nil, fmt.Errorf("%w: chunk type", errCBOR)
					}
					s = append(s, c...)
				default:
					return nil, fmt.Errorf("%w: chunk type", errCBOR)
				}
			}
		} else {
			if arg > uint64(len(r.b)-r.i) {
				return nil, fmt.Errorf("%w: truncated string", errCBOR)
			}
			s = append([]byte{}, r.b[r.i:r.i+int(arg)]...)
			r.i += int(arg)
		}
		if major == 3 {
			return string(s), nil
		}
		return s, nil
	case 4:
		out := []any{}
		for n := uint64(0); info == 31 || n < arg; n++ {
			if info != 31 && arg > uint64(len(r.b)) {
				return nil, fmt.Errorf("%w: truncated array", errCBOR)
			}
			v, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if v == cborBreak {
				if info != 31 {
					return nil, fmt.Errorf("%w: break inside a definite array", errCBOR)
				}
				break
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		out := map[any]any{}
		for n := uint64(0); info == 31 || n < arg; n++ {
			if info != 31 && arg > uint64(len(r.b)) {
				return nil, fmt.Errorf("%w: truncated map", errCBOR)
			}
			k, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if k == cborBreak {
				if info != 31 {
					return nil, fmt.Errorf("%w: break inside a definite map", errCBOR)
				}
				break
			}
			switch k.(type) {
			case uint64, int64, string:
			default:
				return nil, fmt.Errorf("%w: map key of type %T", errCBOR, k)
			}
			v, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if v == cborBreak {
				return nil, fmt.Errorf("%w: map key without value", errCBOR)
			}
			out[k] = v
		}
		return out, nil
	case 6:
		v, err := r.value(depth + 1)
		if err != nil {
			return nil, err
		}
		return cborTag{Num: arg, Val: v}, nil
	}
	// major 7
	switch {
	case info == 20:
		return false, nil
	case info == 21:
		return true, nil
	case info == 22, info == 23:
		return nil, nil
	case info == 25:
		return halfFloat(uint16(arg)), nil
	case info == 26:
		return float64(math.Float32frombits(uint32(arg))), nil
	case info == 27:
		return math.Float64frombits(arg), nil
	case info == 31:
		return cborBreak, nil
	}
	return arg, nil // other simple values
}

func halfFloat(h uint16) float64 {
	exp := int(h >> 10 & 0x1F)
	mant := float64(h & 0x3FF)
	var v float64
	switch exp {
	case 0:
		v = math.Ldexp(mant, -24)
	case 31:
		if mant == 0 {
			v = math.Inf(1)
		} else {
			v = math.NaN()
		}
	default:
		v = math.Ldexp(mant+1024, exp-25)
	}
	if h&0x8000 != 0 {
		v = -v
	}
	return v
}

// cborUint reads an unsigned integer value.
func cborUint(v any) (uint64, bool) {
	u, ok := v.(uint64)
	return u, ok
}

// cborInt reads a signed or unsigned integer value.
func cborInt(v any) (int64, bool) {
	switch x := v.(type) {
	case uint64:
		if x > math.MaxInt64 {
			return 0, false
		}
		return int64(x), true
	case int64:
		return x, true
	}
	return 0, false
}

// cborGet looks an integer key up in a decoded map.
func cborGet(m map[any]any, k int64) (any, bool) {
	if k >= 0 {
		v, ok := m[uint64(k)]
		return v, ok
	}
	v, ok := m[k]
	return v, ok
}

// ---- writer -----------------------------------------------------------------

func cborHead(b []byte, major byte, arg uint64) []byte {
	m := major << 5
	switch {
	case arg < 24:
		return append(b, m|byte(arg))
	case arg <= math.MaxUint8:
		return append(b, m|24, byte(arg))
	case arg <= math.MaxUint16:
		return binary.BigEndian.AppendUint16(append(b, m|25), uint16(arg))
	case arg <= math.MaxUint32:
		return binary.BigEndian.AppendUint32(append(b, m|26), uint32(arg))
	}
	return binary.BigEndian.AppendUint64(append(b, m|27), arg)
}

func cborAppendUint(b []byte, v uint64) []byte { return cborHead(b, 0, v) }

func cborAppendInt(b []byte, v int64) []byte {
	if v >= 0 {
		return cborHead(b, 0, uint64(v))
	}
	return cborHead(b, 1, uint64(-1-v))
}

func cborAppendBytes(b, s []byte) []byte { return append(cborHead(b, 2, uint64(len(s))), s...) }

func cborAppendText(b []byte, s string) []byte { return append(cborHead(b, 3, uint64(len(s))), s...) }
