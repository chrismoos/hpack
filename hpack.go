// Implements the HPACK Header Compression specification
// https://tools.ietf.org/html/rfc7541
//
// The Huffman decoding is implemented with multi-level lookup tables for high performance.
package hpack

import (
	"errors"
	"fmt"
)

type Header struct {
	Name  string
	Value string

	Sensitive bool
}

var ErrIntegerValueTooLarge = errors.New("integer value larger than max value")
var ErrIntegerEncodedLengthTooLong = errors.New("integer encoded length is too long")
var ErrStringLiteralLengthTooLong = errors.New("string literal length is too long")

var DefaultMaxIntegerValue = ((1 << 32) - 1)
var DefaultMaxIntegerEncodedLength = 6
var DefaultMaxStringLiteralLength = 1024 * 64

type Encoder struct {
	dynamicTable                  []Header
	dynamicTableSizeMax           int
	dynamicTableSizeCurrent       int
	pendingDynamicTableSizeUpdate bool
}

// A decoder is stateful and updates the internal compression context during processing
// of header blocks.
//
// If HTTP/2 is used, a single decoder instance must be used during the lifetime of a connection, see:
// https://tools.ietf.org/html/rfc7540#section-4.3
type Decoder struct {
	dynamicTable            []Header
	dynamicTableSizeMax     int
	dynamicTableSizeCurrent int

	integerValueMax         int
	integerEncodedLengthMax int
	stringLiteralLengthMax  int
}

const (
	headerFieldIndexed                 = 128
	headerFieldLiteralIncrementalIndex = 64
	headerFieldDynamicSizeUpdate       = 32
	headerFieldLiteralNeverIndexed     = 16
	headerFieldLiteralNotIndexed       = 0
)

const (
	huffmanEncoded = 1 << 7
)

func NewEncoder(dynamicTableSizeMax int) *Encoder {
	return &Encoder{
		dynamicTableSizeMax:           dynamicTableSizeMax,
		dynamicTableSizeCurrent:       0,
		pendingDynamicTableSizeUpdate: false,
	}
}

func NewDecoder(dynamicTableSizeMax int) *Decoder {
	return &Decoder{
		dynamicTableSizeMax:     dynamicTableSizeMax,
		dynamicTableSizeCurrent: 0,
		integerEncodedLengthMax: DefaultMaxIntegerEncodedLength,
		integerValueMax:         DefaultMaxIntegerValue,
		stringLiteralLengthMax:  DefaultMaxStringLiteralLength,
	}
}

func (decoder *Decoder) readPrefixedLengthString(buf []byte, prefixLength int) (remainingBuf []byte, str string, err error) {
	rest, huffman, length, err := decoder.DecodeInteger(buf, prefixLength)
	if err != nil {
		return buf, "", err
	}

	if length > decoder.stringLiteralLengthMax {
		return buf, "", ErrStringLiteralLengthTooLong
	}

	if huffman&huffmanEncoded == huffmanEncoded {
		if len(rest) < length {
			return nil, "", fmt.Errorf("ran out of data while decoding huffman encoded data")
		}
		decoded, err := HuffmanDecode(rest[:length])
		if err != nil {
			return rest, "", err
		}
		return rest[length:], string(decoded), nil
	} else {
		return rest[length:], string(rest[:length]), nil
	}
}

func (decoder *Decoder) getIndexedNameValue(index int) (string, string, error) {
	if index > len(staticTable) {
		dynamicIndex := index - len(staticTable)
		if dynamicIndex > len(decoder.dynamicTable) {
			return "", "", fmt.Errorf("index %d not found in dynamic table", index)
		}
		return decoder.dynamicTable[dynamicIndex-1].Name, decoder.dynamicTable[dynamicIndex-1].Value, nil
	}
	return staticTable[index-1][0], staticTable[index-1][1], nil
}

// Updates the decoder's dynamic table maximum size and evicts any
// headers if more space is needed to resize to newMaxSize.
func (decoder *Decoder) SetDynamicTableMaxSize(newMaxSize int) {
	decoder.dynamicTableSizeMax = newMaxSize
	decoder.evictEntries(0, newMaxSize)
}

// Sets the largest integer that is allowed, anything > value will result in an error
func (decoder *Decoder) SetMaxIntegerValue(value int) {
	decoder.integerValueMax = value
}

// Sets the maximum bytes allowed for encoding a single integer
func (decoder *Decoder) SetMaxIntegerEncodedLength(length int) {
	decoder.integerEncodedLengthMax = length
}

// Sets the maximum length of a string literal
// For compressed string literals the length check will be against the
// compressed length, not the uncompressed length
func (decoder *Decoder) SetMaxStringLiteralLength(length int) {
	decoder.stringLiteralLengthMax = length
}

// Finds the header in the table.
// Returns the index and a bool indicating if the entry includes the value also.
// If the entry wasn't found the index returned is -1
func (encoder *Encoder) findHeaderInTable(name string, value string) (int, bool) {
	var entry int
	var ok bool

	if value != "" {
		entry, ok = staticTableEncodingWithValues[name+":"+value]
		if ok {
			return entry, true
		}
	}

	for x, header := range encoder.dynamicTable {
		if header.Name == name && header.Value == value {
			return len(staticTable) + x + 1, true
		}
	}

	entry, ok = staticTableEncoding[name]
	if ok {
		return entry, false
	}
	return -1, false
}

// Updates the encoder's dynamic table maximum size and evicts any
// headers if more space is needed to resize to newMaxSize.
//
// After this call the next header field that is encoded will include
// a dynamic table size update
func (encoder *Encoder) SetDynamicTableMaxSize(newMaxSize int) {
	encoder.dynamicTableSizeMax = newMaxSize
	encoder.evictEntries(0, newMaxSize)
	encoder.pendingDynamicTableSizeUpdate = true
}

func findStaticEntryInTable(name string) int {
	entry, ok := staticTableEncoding[name]
	if ok {
		return entry
	}
	return -1
}

// This is a convenience function that encodes a list of headers
// into a header block using Huffman compression and with incremental
// indexing enabled.
//
// If a header is marked as Sensitive it will be encoded as a
// never indexed header field
func (encoder *Encoder) Encode(headers []Header) ([]byte, error) {
	return encoder.encode(headers, true)
}

func encodeLiteralString(str string, prefixLength int, huffman bool) []byte {
	encoded := make([]byte, 0)

	var value []byte
	if huffman {
		value = HuffmanEncode([]byte(str))
	} else {
		value = []byte(str)
	}
	valueLen := encodeInteger(len(value), prefixLength)

	if huffman {
		valueLen[0] |= huffmanEncoded
	}
	encoded = append(encoded, valueLen...)
	encoded = append(encoded, value...)
	return encoded
}

// Encodes a header without Indexing and returns the encoded header field
//
// https://tools.ietf.org/html/rfc7541#appendix-C.2.2
func (encoder *Encoder) EncodeNoDynamicIndexing(header Header, huffman bool) ([]byte, error) {
	return encoder.encodeHeaderField(header, huffman, false)
}

// Encodes a header with Indexing and returns the encoded header field
//
// https://tools.ietf.org/html/rfc7541#appendix-C.2.1
func (encoder *Encoder) EncodeIndexed(header Header, huffman bool) ([]byte, error) {
	return encoder.encodeHeaderField(header, huffman, true)
}

func (encoder *Encoder) encodeHeaderField(header Header, huffman bool, addDynamicIndex bool) ([]byte, error) {
	encoded := make([]byte, 0)

	if encoder.pendingDynamicTableSizeUpdate {
		newSize := encodeInteger(encoder.dynamicTableSizeMax, 5)
		newSize[0] |= headerFieldDynamicSizeUpdate
		encoded = append(encoded, newSize...)
		encoder.pendingDynamicTableSizeUpdate = false
	}

	if header.Sensitive {
		index := findStaticEntryInTable(header.Name)
		if index != -1 {
			indexed := encodeInteger(index, 4)
			indexed[0] |= headerFieldLiteralNeverIndexed
			encoded = append(encoded, indexed...)
		} else {
			indexed := encodeInteger(0, 4)
			indexed[0] |= headerFieldLiteralNeverIndexed
			encoded = append(encoded, indexed...)
			encoded = append(encoded, encodeLiteralString(header.Name, 7, huffman)...)
		}

		encoded = append(encoded, encodeLiteralString(header.Value, 7, huffman)...)
	} else {
		index, valueIndexed := encoder.findHeaderInTable(header.Name, header.Value)
		if index != -1 && valueIndexed {
			indexed := encodeInteger(index, 7)
			indexed[0] |= headerFieldIndexed
			encoded = append(encoded, indexed...)
		} else {
			var indexed []byte
			if index == -1 {
				indexed = encodeInteger(0, 6)
			} else {
				indexed = encodeInteger(index, 6)
			}

			if addDynamicIndex {
				indexed[0] |= headerFieldLiteralIncrementalIndex
				encoder.addNewDynamicEntry(header.Name, header.Value)
			} else {
				indexed[0] |= headerFieldLiteralNotIndexed
			}

			encoded = append(encoded, indexed...)
			if index == -1 {
				encoded = append(encoded, encodeLiteralString(header.Name, 7, huffman)...)
			}

			encoded = append(encoded, encodeLiteralString(header.Value, 7, huffman)...)
		}
	}
	return encoded, nil
}

func (encoder *Encoder) encode(headers []Header, huffman bool) ([]byte, error) {
	encoded := make([]byte, 0)
	for _, header := range headers {
		enc, err := encoder.EncodeIndexed(header, huffman)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, enc...)
	}
	return encoded, nil
}

// Parsers the HPACK header block and returns list of headers
// with the order preserved from the order in the block.
func (decoder *Decoder) Decode(block []byte) ([]Header, error) {
	headers := make([]Header, 0)
	buf := block
	for len(buf) > 0 {
		var header *Header
		var err error

		buf, header, err = decoder.parseHeaderField(buf)
		if err != nil {
			return nil, err
		}
		if header != nil {
			headers = append(headers, *header)
		}
	}
	return headers, nil
}

// Returns true if there is enough space to accomadate additionalSize
func (encoder *Encoder) evictEntries(additionalSize int, maxSize int) bool {
	for encoder.dynamicTableSizeCurrent+additionalSize > maxSize {
		if len(encoder.dynamicTable) == 0 {
			return false
		}

		evictedEntry := encoder.dynamicTable[len(encoder.dynamicTable)-1]
		encoder.dynamicTableSizeCurrent -= (32 + len(evictedEntry.Name) + len(evictedEntry.Value))
		encoder.dynamicTable = encoder.dynamicTable[:len(encoder.dynamicTable)-1]
	}
	return true
}

// Returns true if there is enough space to accomadate additionalSize
func (decoder *Decoder) evictEntries(additionalSize int, maxSize int) bool {
	for decoder.dynamicTableSizeCurrent+additionalSize > maxSize {
		if len(decoder.dynamicTable) == 0 {
			return false
		}

		evictedEntry := decoder.dynamicTable[len(decoder.dynamicTable)-1]
		decoder.dynamicTableSizeCurrent -= (32 + len(evictedEntry.Name) + len(evictedEntry.Value))
		decoder.dynamicTable = decoder.dynamicTable[:len(decoder.dynamicTable)-1]
	}
	return true
}

func (encoder *Encoder) addNewDynamicEntry(name string, value string) {
	entrySize := (32 + len(name) + len(value))

	if !encoder.evictEntries(entrySize, encoder.dynamicTableSizeMax) {
		return
	}
	encoder.dynamicTableSizeCurrent += entrySize

	encoder.dynamicTable = append([]Header{
		{
			Name:  name,
			Value: value,
		},
	}, encoder.dynamicTable...)
}

func (decoder *Decoder) addNewDynamicEntry(name string, value string) {
	entrySize := (32 + len(name) + len(value))

	if !decoder.evictEntries(entrySize, decoder.dynamicTableSizeMax) {
		return
	}
	decoder.dynamicTableSizeCurrent += entrySize

	decoder.dynamicTable = append([]Header{
		{
			Name:  name,
			Value: value,
		},
	}, decoder.dynamicTable...)
}

func (decoder *Decoder) parseHeaderFieldIndexed(encoded []byte) ([]byte, *Header, error) {
	rest, _, index, err := decoder.DecodeInteger(encoded, 7)
	if err != nil {
		return nil, nil, err
	}

	name, value, err := decoder.getIndexedNameValue(index)
	if err != nil {
		return nil, nil, err
	}
	return rest, &Header{Name: name, Value: value}, nil
}

func (decoder *Decoder) parseHeaderFieldIncrementalIndex(encoded []byte) ([]byte, *Header, error) {
	rest, _, index, err := decoder.DecodeInteger(encoded, 6)
	if err != nil {
		return nil, nil, err
	}

	var name string
	if index == 0 {
		rest, name, err = decoder.readPrefixedLengthString(rest, 7)
		if err != nil {
			return nil, nil, err
		}
	} else {
		name, _, err = decoder.getIndexedNameValue(index)
		if err != nil {
			return nil, nil, err
		}
	}

	rest, value, err := decoder.readPrefixedLengthString(rest, 7)
	if err != nil {
		return nil, nil, err
	}

	decoder.addNewDynamicEntry(name, value)
	return rest, &Header{Name: name, Value: value}, nil
}

func (decoder *Decoder) parseDynamicSizeUpdate(encoded []byte) ([]byte, error) {
	consumed, _, size, err := decoder.DecodeInteger(encoded, 5)
	if err != nil {
		return nil, err
	}
	if size > decoder.dynamicTableSizeMax {
		return consumed, fmt.Errorf("can't resize dynamic table to %d in an update to a value greater than the current size, %d", size, decoder.dynamicTableSizeCurrent)
	}
	decoder.SetDynamicTableMaxSize(size)
	return consumed, nil
}

func (decoder *Decoder) parseHeaderFieldNotIndexed(encoded []byte) ([]byte, *Header, error) {
	rest, _, index, err := decoder.DecodeInteger(encoded, 4)
	if err != nil {
		return nil, nil, err
	}
	if index == 0 {
		rest, name, err := decoder.readPrefixedLengthString(rest, 7)
		if err != nil {
			return nil, nil, err
		}

		rest, value, err := decoder.readPrefixedLengthString(rest, 7)
		if err != nil {
			return nil, nil, err
		}

		return rest, &Header{Name: name, Value: value}, nil

	} else {
		name, _, err := decoder.getIndexedNameValue(index)
		if err != nil {
			return nil, nil, err
		}

		rest, value, err := decoder.readPrefixedLengthString(rest, 7)
		if err != nil {
			return nil, nil, err
		}

		return rest, &Header{Name: name, Value: value}, nil
	}
}

func (decoder *Decoder) parseHeaderField(encoded []byte) ([]byte, *Header, error) {
	if encoded[0]&headerFieldIndexed == headerFieldIndexed {
		return decoder.parseHeaderFieldIndexed(encoded)
	} else if encoded[0]&headerFieldLiteralIncrementalIndex == headerFieldLiteralIncrementalIndex {
		return decoder.parseHeaderFieldIncrementalIndex(encoded)
	} else if encoded[0]&headerFieldDynamicSizeUpdate == headerFieldDynamicSizeUpdate {
		rest, err := decoder.parseDynamicSizeUpdate(encoded)
		if err != nil {
			return rest, nil, err
		}
		return rest, nil, nil
	} else if encoded[0]&headerFieldLiteralNeverIndexed == headerFieldLiteralNeverIndexed {
		rest, header, err := decoder.parseHeaderFieldNotIndexed(encoded)
		if err != nil {
			return rest, header, err
		} else {
			header.Sensitive = true
			return rest, header, err
		}
	} else if encoded[0]&headerFieldLiteralNotIndexed == headerFieldLiteralNotIndexed {
		return decoder.parseHeaderFieldNotIndexed(encoded)
	} else {
		panic(fmt.Errorf("unknown type: %02x", encoded[0]))
	}
}
