package hpack

import (
	"math"
)

// Decodes an integer from buf with the specified prefix length in number of bits.
//
// This function returns the remaining buffer after fully parsing the integer, the first octet with a mask applied to remove the prefix,
// the decoded number, and an error if an error occurred while parsing.
//
// See https://tools.ietf.org/html/rfc7541#section-5.1
func (decoder *Decoder) DecodeInteger(buf []byte, prefixLength int) (remainingBuf []byte, maskedFirstOctet int, number int, err error) {
	return decodeInteger(buf, prefixLength, decoder.integerValueMax, decoder.integerEncodedLengthMax)
}

func decodeInteger(buf []byte, prefixLength int, integerMax int, encodedLengthMax int) (remainingBuf []byte, maskedFirstOctet int, number int, err error) {
	if prefixLength < 1 || prefixLength > 8 {
		panic("prefix length in bits must be >= 1 and <= 8")
	}
	mask := (1<<uint(prefixLength) - 1)
	n := mask & int(buf[0])
	prefix := int(buf[0]) &^ mask
	if n != mask {
		return buf[1:], prefix, n, nil
	} else {
		idx := 1
		m := 0
		for {
			if idx == len(buf) {
				panic("ran out of data while reading HPACK integer")
			}
			n += (int(buf[idx]) & 127) * int(math.Pow(2, float64(m)))
			if buf[idx]&(1<<7) == 0 {
				if n > integerMax {
					return nil, 0, 0, ErrIntegerValueTooLarge
				}
				return buf[idx+1:], prefix, n, nil
			}
			m += 7
			idx += 1
			if idx == encodedLengthMax {
				return nil, 0, 0, ErrIntegerEncodedLengthTooLong
			}
		}
	}
}

// Encodes number with the specified prefix length in number of bits.
//
// See https://tools.ietf.org/html/rfc7541#section-5.1
func (encoder *Encoder) EncodeInteger(number int, prefixLength int) []byte {
	return encodeInteger(number, prefixLength)
}

func encodeInteger(number int, prefixLength int) []byte {
	if prefixLength < 1 || prefixLength > 8 {
		panic("prefix length in bits must be >= 1 and <= 8")
	}
	if number < int(math.Pow(2, float64(prefixLength)))-1 {
		return []byte{byte(number)}
	} else {
		i := number
		buf := []byte{byte(int(math.Pow(2, float64(prefixLength))) - 1)}
		i -= (int(math.Pow(2, float64(prefixLength))) - 1)
		for i >= 128 {
			buf = append(buf, byte((i%128)+128))
			i /= 128
		}
		buf = append(buf, byte(i))
		return buf
	}
}
