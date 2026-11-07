package auth

// The CBOR codec @simplewebauthn/server uses (@levischuck/tiny-cbor 0.2), quirks included, so attestation objects,
// authenticator data and COSE keys decode exactly as in the TypeScript service, and a credential public key is
// re-encoded to the same bytes before it is stored (the passkey record's publicKey).

import (
	"encoding/binary"
	"errors"
	"math"
)

// cborUndefined is CBOR undefined (simple value 23).
type cborUndefined struct{}

// cborTag is a tagged item.
type cborTag struct {
	Tag   float64
	Value any
}

// cborKey is a map key: a string or a number (JavaScript Map keys, compared by SameValueZero).
type cborKey struct {
	isString bool
	text     string
	number   float64
}

func (k cborKey) value() any {
	if k.isString {
		return k.text
	}
	return k.number
}

// cborMap is a JavaScript Map with string or number keys, in insertion order.
type cborMap struct {
	keys   []cborKey
	values map[cborKey]any
}

func newCBORMap() *cborMap { return &cborMap{values: map[cborKey]any{}} }

func keyOf(key any) cborKey {
	switch k := key.(type) {
	case string:
		return cborKey{isString: true, text: k}
	case float64:
		if k == 0 {
			k = 0 // -0 and +0 are one key
		}
		return cborKey{number: k}
	case int:
		return cborKey{number: float64(k)}
	}
	return cborKey{}
}

func (m *cborMap) set(key any, value any) {
	k := keyOf(key)
	if _, ok := m.values[k]; !ok {
		m.keys = append(m.keys, k)
	}
	m.values[k] = value
}

// get returns the member for a string or number key (nil, false when absent).
func (m *cborMap) get(key any) (any, bool) {
	if m == nil {
		return nil, false
	}
	value, ok := m.values[keyOf(key)]
	return value, ok
}

func (m *cborMap) size() int {
	if m == nil {
		return 0
	}
	return len(m.keys)
}

var errCBORLength = errors.New("Length not supported or not well formed")

// cborLength is decodeLength: the argument of a header at data[index].
func cborLength(data []byte, argument byte, index int) (float64, int, error) {
	if argument < 24 {
		return float64(argument), 1, nil
	}
	remaining := len(data) - index - 1
	var output uint64
	var size int
	switch argument {
	case 24:
		if remaining > 0 {
			output, size = uint64(data[index+1]), 2
		}
	case 25:
		if remaining > 1 {
			output, size = uint64(binary.BigEndian.Uint16(data[index+1:])), 3
		}
	case 26:
		if remaining > 3 {
			output, size = uint64(binary.BigEndian.Uint32(data[index+1:])), 5
		}
	case 27:
		if remaining > 7 {
			big := binary.BigEndian.Uint64(data[index+1:])
			if big >= 24 && big <= 9007199254740991 {
				return float64(big), 9, nil
			}
		}
		return 0, 0, errCBORLength
	}
	if output != 0 && output >= 24 {
		return float64(output), size, nil
	}
	return 0, 0, errCBORLength
}

// cborBytes is decodeByteString: a declared length past the end yields the bytes that are there (the consumed
// length still counts the declared one), as ArrayBuffer#slice does.
func cborBytes(data []byte, argument byte, index int) ([]byte, int, error) {
	length, consumed, err := cborLength(data, argument, index)
	if err != nil {
		return nil, 0, err
	}
	start := index + consumed
	end := start + int(length)
	if start > len(data) {
		start = len(data)
	}
	if end > len(data) {
		end = len(data)
	}
	return append([]byte(nil), data[start:end]...), consumed + int(length), nil
}

func cborDecodeNext(data []byte, index int, depth int) (any, int, error) {
	if index >= len(data) {
		return nil, 0, errors.New("CBOR stream ended before tag value")
	}
	if depth > 512 {
		return nil, 0, errors.New("CBOR nesting too deep")
	}
	b := data[index]
	major := b >> 5
	argument := b & 0x1f
	switch major {
	case 0:
		value, consumed, err := cborLength(data, argument, index)
		return value, consumed, err
	case 1:
		value, consumed, err := cborLength(data, argument, index)
		if err != nil {
			return nil, 0, err
		}
		return -value - 1, consumed, nil
	case 2:
		return cborBytes(data, argument, index)
	case 3:
		raw, consumed, err := cborBytes(data, argument, index)
		if err != nil {
			return nil, 0, err
		}
		return decodeUTF8(raw), consumed, nil
	case 4:
		if argument == 0 {
			return []any{}, 1, nil
		}
		length, consumed, err := cborLength(data, argument, index)
		if err != nil {
			return nil, 0, err
		}
		out := []any{}
		for i := 0; i < int(length); i++ {
			if len(data)-index-consumed <= 0 {
				return nil, 0, errors.New("array is not supported or well formed")
			}
			value, used, err := cborDecodeNext(data, index+consumed, depth+1)
			if err != nil {
				return nil, 0, err
			}
			out = append(out, value)
			consumed += used
		}
		return out, consumed, nil
	case 5:
		if argument == 0 {
			return newCBORMap(), 1, nil
		}
		length, consumed, err := cborLength(data, argument, index)
		if err != nil {
			return nil, 0, err
		}
		mapError := errors.New("Map is not supported or well formed")
		out := newCBORMap()
		for i := 0; i < int(length); i++ {
			remaining := len(data) - index - consumed
			if remaining <= 0 {
				return nil, 0, mapError
			}
			key, used, err := cborDecodeNext(data, index+consumed, depth+1)
			if err != nil {
				return nil, 0, err
			}
			consumed += used
			remaining -= used
			if remaining <= 0 {
				return nil, 0, mapError
			}
			switch key.(type) {
			case string, float64:
			default:
				return nil, 0, mapError
			}
			if _, exists := out.get(key); exists {
				return nil, 0, mapError
			}
			value, used, err := cborDecodeNext(data, index+consumed, depth+1)
			if err != nil {
				return nil, 0, err
			}
			consumed += used
			out.set(key, value)
		}
		return out, consumed, nil
	case 6:
		tag, consumed, err := cborLength(data, argument, index)
		if err != nil {
			return nil, 0, err
		}
		value, used, err := cborDecodeNext(data, index+consumed, depth+1)
		if err != nil {
			return nil, 0, err
		}
		return &cborTag{Tag: tag, Value: value}, consumed + used, nil
	case 7:
		switch argument {
		case 20:
			return false, 1, nil
		case 21:
			return true, 1, nil
		case 22:
			return nil, 1, nil
		case 23:
			return cborUndefined{}, 1, nil
		case 25:
			if index+3 > len(data) {
				return nil, 0, errors.New("CBOR stream ended before end of Float 16")
			}
			switch binary.BigEndian.Uint16(data[index+1:]) {
			case 0x7c00:
				return math.Inf(1), 3, nil
			case 0x7e00:
				return math.NaN(), 3, nil
			case 0xfc00:
				return math.Inf(-1), 3, nil
			}
			return nil, 0, errors.New("Float16 data is unsupported")
		case 26:
			if index+5 > len(data) {
				return nil, 0, errors.New("CBOR stream ended before end of Float 32")
			}
			return float64(math.Float32frombits(binary.BigEndian.Uint32(data[index+1:]))), 5, nil
		case 27:
			if index+9 > len(data) {
				return nil, 0, errors.New("CBOR stream ended before end of Float 64")
			}
			return math.Float64frombits(binary.BigEndian.Uint64(data[index+1:])), 9, nil
		}
	}
	return nil, 0, errors.New("Unsupported or not well formed")
}

// cborDecodeFirst is isoCBOR.decodeFirst: the first item of the input (trailing bytes are ignored).
func cborDecodeFirst(data []byte) (any, error) {
	if len(data) == 0 {
		return nil, errors.New("No data")
	}
	value, _, err := cborDecodeNext(data, 0, 0)
	return value, err
}

func cborHeader(major byte, argument uint64) []byte {
	m := major << 5
	switch {
	case argument <= 23:
		return []byte{m | byte(argument)}
	case argument <= 255:
		return []byte{m | 24, byte(argument)}
	case argument <= 65535:
		return []byte{m | 25, byte(argument >> 8), byte(argument)}
	case argument <= 4294967295:
		out := []byte{m | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(out[1:], uint32(argument))
		return out
	}
	out := []byte{m | 27, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(out[1:], argument)
	return out
}

// cborEncode is isoCBOR.encode. Text strings carry their UTF-16 length in the header (as tiny-cbor writes it).
func cborEncode(value any) ([]byte, error) {
	var out []byte
	var write func(value any) error
	write = func(value any) error {
		switch v := value.(type) {
		case nil, cborUndefined:
			if v == nil {
				out = append(out, 0xf6)
			} else {
				out = append(out, 0xf7)
			}
		case bool:
			if v {
				out = append(out, 0xf5)
			} else {
				out = append(out, 0xf4)
			}
		case float64:
			if v == math.Trunc(v) && math.Abs(v) <= 9007199254740991 {
				if v < 0 {
					// encodeLength(NEGATIVE, |v|) subtracts one.
					out = append(out, cborHeader(1, uint64(-v)-1)...)
				} else {
					out = append(out, cborHeader(0, uint64(v))...)
				}
				return nil
			}
			if float64(float32(v)) == v || math.IsInf(v, 0) || math.IsNaN(v) {
				buffer := []byte{0xfa, 0, 0, 0, 0}
				binary.BigEndian.PutUint32(buffer[1:], math.Float32bits(float32(v)))
				out = append(out, buffer...)
			} else {
				buffer := []byte{0xfb, 0, 0, 0, 0, 0, 0, 0, 0}
				binary.BigEndian.PutUint64(buffer[1:], math.Float64bits(v))
				out = append(out, buffer...)
			}
		case string:
			out = append(out, cborHeader(3, uint64(utf16Length(v)))...)
			out = append(out, utf8Bytes(v)...)
		case []byte:
			out = append(out, cborHeader(2, uint64(len(v)))...)
			out = append(out, v...)
		case []any:
			out = append(out, cborHeader(4, uint64(len(v)))...)
			for _, item := range v {
				if err := write(item); err != nil {
					return err
				}
			}
		case *cborMap:
			out = append(out, cborHeader(5, uint64(v.size()))...)
			for _, key := range v.keys {
				if err := write(key.value()); err != nil {
					return err
				}
				if err := write(v.values[key]); err != nil {
					return err
				}
			}
		case *cborTag:
			out = append(out, cborHeader(6, uint64(v.Tag))...)
			return write(v.Value)
		default:
			return errors.New("Not implemented")
		}
		return nil
	}
	if err := write(value); err != nil {
		return nil, err
	}
	return out, nil
}

func utf16Length(s string) int {
	n := 0
	for _, r := range runes(s) {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}
