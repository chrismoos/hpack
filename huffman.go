package hpack

import "errors"

type bitReader struct {
	buf      []byte
	index    int
	bitIndex int
}

func newBitReader(buf []byte) *bitReader {
	return &bitReader{
		buf:      buf,
		index:    0,
		bitIndex: 0,
	}
}

var ErrHuffmanDecodeFailure = errors.New("invalid huffman code encountered")

func (br *bitReader) PeekBits(numBits int) (int, int) {
	var n int = 0
	var idx int = br.index
	var bitIdx int = br.bitIndex
	for x := numBits; x >= 0; {
		for y := 0; y < 8; y++ {
			var bit int = 0
			if ((br.buf[idx] << uint(bitIdx)) & (1 << 7)) == (1 << 7) {
				bit = 1
			}
			n |= (bit << uint(x-1))

			bitIdx += 1
			if bitIdx == 8 {
				bitIdx = 0
				idx += 1
				if idx == len(br.buf) {
					return n, (numBits - x + 1)
				}
			}
			x -= 1
		}
	}
	return n, numBits
}

func (br *bitReader) BitsAvailable() int {
	bytes := len(br.buf) - br.index
	return (8 * bytes) - br.bitIndex
}

func (br *bitReader) ConsumeBits(numBits int) {
	br.index += (numBits + br.bitIndex) / 8
	br.bitIndex = (numBits + br.bitIndex) % 8
}

// Encodes the specified data with Huffman codes in HPACK
func HuffmanEncode(data []byte) []byte {
	encoded := make([]byte, 0)
	var currentByte byte = 0
	currentBits := 0
	for _, b := range data {
		entry := huffmanCodes[b]
		code := entry[0]
		bits := int(entry[1])
		bitsRemaining := bits

		for bitsRemaining > 0 {
			if (code>>uint(bitsRemaining-1))&1 == 1 {
				currentByte |= 1
			}
			bitsRemaining -= 1
			currentBits += 1
			if currentBits == 8 {
				encoded = append(encoded, currentByte)
				currentByte = 0
				currentBits = 0
			} else {
				currentByte <<= 1
			}
		}
	}
	if currentBits > 0 && currentBits < 8 {
		padding := huffmanCodes[256]
		currentByte <<= 7 - uint(currentBits)
		currentByte |= byte(padding[0] >> (padding[1] - uint32(8-currentBits)))
		encoded = append(encoded, currentByte)
	}
	return encoded
}

// Decodes the huffman encoded data
func HuffmanDecode(encoded []byte) ([]byte, error) {
	decoded := make([]byte, 0)

	bitReader := newBitReader(encoded)
	for bitReader.BitsAvailable() >= 5 {
		n, bitsRead := bitReader.PeekBits(32)
		code := int32(n)
		decode_success := false

		table := lookupTable
		for bitIdx := 0; bitIdx < 32; bitIdx += 8 {
			entry := table[(code>>(24-uint(bitIdx)))&0xff]
			if entry != nil {
				if entry.nextTable != nil {
					table = entry.nextTable
				} else {
					if bitsRead >= int(entry.bits) {
						decoded = append(decoded, []byte{byte(entry.symbol)}...)
					}
					bitReader.ConsumeBits(int(entry.bits))
					decode_success = true
					break
				}
			}
		}
		if !decode_success {
			if bitsRead <= 7 {
				break
			} else {
				return nil, ErrHuffmanDecodeFailure
			}
		}
	}
	return decoded, nil
}
