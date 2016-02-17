package hpack

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestExampleC11ParseInteger(t *testing.T) {
	encoded := []byte{0x8A}
	decoder := NewDecoder(256)
	_, _, decoded, err := decoder.DecodeInteger(encoded, 5)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 10, decoded)
}

func TestExampleC11ParseWrite(t *testing.T) {
	assert.Equal(t, []byte{byte(10)}, encodeInteger(10, 5))
}

func TestExampleC12ParseInteger(t *testing.T) {
	encoded := []byte{31, 154, 10}
	decoder := NewDecoder(256)
	_, _, decoded, err := decoder.DecodeInteger(encoded, 5)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1337, decoded)
}

func TestExampleC12ParseWrite(t *testing.T) {
	assert.Equal(t, []byte{31, 154, 10}, encodeInteger(1337, 5))
}

func TestExampleC13ParseInteger(t *testing.T) {
	encoded := []byte{42}
	decoder := NewDecoder(256)
	_, _, decoded, err := decoder.DecodeInteger(encoded, 8)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 42, decoded)
}

func TestExampleC13ParseWrite(t *testing.T) {
	assert.Equal(t, []byte{42}, encodeInteger(42, 8))
}

func TestEncodeHeaderNeverIndexed(t *testing.T) {
	items := [][3]string{
		{"100870617373776f726406736563726574", "password", "secret"},
	}

	for _, item := range items {
		encoder := NewEncoder(256)
		encoded, err := encoder.EncodeIndexed(Header{Name: item[1], Value: item[2], Sensitive: true}, false)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, item[0], hex.EncodeToString(encoded))
	}
}

func TestParseHeaderNeverIndexed(t *testing.T) {
	items := [][3]string{
		{"100870617373776f726406736563726574", "password", "secret"},
	}

	for _, item := range items {
		encodedHex := []byte(item[0])
		encoded := make([]byte, len(encodedHex)/2)
		_, err := hex.Decode(encoded, encodedHex)
		if err != nil {
			t.Fatal(err)
		}
		decoder := NewDecoder(256)
		_, header, err := decoder.parseHeaderField(encoded)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, item[1], header.Name)
		assert.Equal(t, item[2], header.Value)
		assert.True(t, header.Sensitive)
	}
}

func TestParseHeaders(t *testing.T) {
	items := [][3]string{
		{"400a637573746f6d2d6b65790d637573746f6d2d686561646572", "custom-key", "custom-header"},
		{"040c2f73616d706c652f70617468", ":path", "/sample/path"},
		{"100870617373776f726406736563726574", "password", "secret"},
		{"82", ":method", "GET"},
	}

	for _, item := range items {
		encodedHex := []byte(item[0])
		encoded := make([]byte, len(encodedHex)/2)
		_, err := hex.Decode(encoded, encodedHex)
		if err != nil {
			t.Fatal(err)
		}
		decoder := NewDecoder(256)
		_, header, err := decoder.parseHeaderField(encoded)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, item[1], header.Name)
		assert.Equal(t, item[2], header.Value)
	}
}

func testHeaderEncoding(t *testing.T, encodedHexValues []string, headers [][]Header, dynamicTable [][]Header, dynamicTableSize int, huffman bool, indexing bool) {
	encoder := NewEncoder(dynamicTableSize)
	for x, _ := range encodedHexValues {
		var encoded []byte
		if indexing {
			for _, header := range headers[x] {
				enc, err := encoder.EncodeIndexed(header, huffman)
				if err != nil {
					t.Fatal(err)
				}
				encoded = append(encoded, enc...)
			}
		} else {
			for _, header := range headers[x] {
				enc, err := encoder.EncodeNoDynamicIndexing(header, huffman)
				if err != nil {
					t.Fatal(err)
				}
				encoded = append(encoded, enc...)
			}
		}
		assert.Equal(t, encodedHexValues[x], hex.EncodeToString(encoded))
		if dynamicTable != nil {
			assert.Equal(t, dynamicTable[x], encoder.dynamicTable)
		}
	}
}

func testHeaderParsing(t *testing.T, encodedHexValues []string, expected [][]Header, dynamicTable [][]Header, dynamicTableSize int) {
	decoder := NewDecoder(dynamicTableSize)
	for x, encodedHex := range encodedHexValues {
		encoded := make([]byte, len(encodedHex)/2)
		_, err := hex.Decode(encoded, []byte(encodedHex))
		if err != nil {
			t.Fatal(err)
		}
		headers, err := decoder.Decode(encoded)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, len(expected[x]), len(headers))
		assert.Equal(t, expected[x], headers)
		if dynamicTable != nil {
			assert.Equal(t, dynamicTable[x], decoder.dynamicTable)
		}
	}
}

func TestEncodeWithNoIndexing(t *testing.T) {
	encodedHexValues := []string{
		"040c2f73616d706c652f70617468",
	}
	headers := [][]Header{
		{
			{":path", "/sample/path", false},
		},
	}

	testHeaderEncoding(t, encodedHexValues, headers, nil, 256, false, false)
}

func TestEncodeWithDynamicTableNoHuffman(t *testing.T) {
	encodedHexValues := []string{
		"828684410f7777772e6578616d706c652e636f6d",
		"828684be58086e6f2d6361636865",
		"828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
	}
	headers := [][]Header{
		{
			{":method", "GET", false},
			{":scheme", "http", false},
			{":path", "/", false},
			{":authority", "www.example.com", false},
		},
		{
			{":method", "GET", false},
			{":scheme", "http", false},
			{":path", "/", false},
			{":authority", "www.example.com", false},
			{"cache-control", "no-cache", false},
		},
		{
			{":method", "GET", false},
			{":scheme", "https", false},
			{":path", "/index.html", false},
			{":authority", "www.example.com", false},
			{"custom-key", "custom-value", false},
		},
	}

	testHeaderEncoding(t, encodedHexValues, headers, nil, 256, false, true)
}

func TestDecodeWithDynamicTableNoHuffman(t *testing.T) {
	encodedHexValues := []string{
		"828684410f7777772e6578616d706c652e636f6d",
		"828684be58086e6f2d6361636865",
		"828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
	}
	expected := [][]Header{
		{
			{":method", "GET", false},
			{":scheme", "http", false},
			{":path", "/", false},
			{":authority", "www.example.com", false},
		},
		{
			{":method", "GET", false},
			{":scheme", "http", false},
			{":path", "/", false},
			{":authority", "www.example.com", false},
			{"cache-control", "no-cache", false},
		},
		{
			{":method", "GET", false},
			{":scheme", "https", false},
			{":path", "/index.html", false},
			{":authority", "www.example.com", false},
			{"custom-key", "custom-value", false},
		},
	}

	testHeaderParsing(t, encodedHexValues, expected, nil, 256)
}

func TestEncodeWithDynamicTableHuffman(t *testing.T) {
	encodedHexValues := []string{
		"828684418cf1e3c2e5f23a6ba0ab90f4ff",
		"828684be5886a8eb10649cbf",
		"828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
	}
	headers := [][]Header{
		{
			{":method", "GET", false},
			{":scheme", "http", false},
			{":path", "/", false},
			{":authority", "www.example.com", false},
		},
		{
			{":method", "GET", false},
			{":scheme", "http", false},
			{":path", "/", false},
			{":authority", "www.example.com", false},
			{"cache-control", "no-cache", false},
		},
		{
			{":method", "GET", false},
			{":scheme", "https", false},
			{":path", "/index.html", false},
			{":authority", "www.example.com", false},
			{"custom-key", "custom-value", false},
		},
	}

	testHeaderEncoding(t, encodedHexValues, headers, nil, 256, true, true)
}

func TestDecodeWithDynamicTableHuffman(t *testing.T) {
	encodedHexValues := []string{
		"828684418cf1e3c2e5f23a6ba0ab90f4ff",
		"828684be5886a8eb10649cbf",
		"828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
	}
	expected := [][]Header{
		{
			{":method", "GET", false},
			{":scheme", "http", false},
			{":path", "/", false},
			{":authority", "www.example.com", false},
		},
		{
			{":method", "GET", false},
			{":scheme", "http", false},
			{":path", "/", false},
			{":authority", "www.example.com", false},
			{"cache-control", "no-cache", false},
		},
		{
			{":method", "GET", false},
			{":scheme", "https", false},
			{":path", "/index.html", false},
			{":authority", "www.example.com", false},
			{"custom-key", "custom-value", false},
		},
	}

	testHeaderParsing(t, encodedHexValues, expected, nil, 256)
}

func TestEncodeWithDynamicTableEvictionsHuffman(t *testing.T) {
	encodedHexValues := []string{
		"488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
		"4883640effc1c0bf",
		"88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
	}
	headers := [][]Header{
		{
			{":status", "302", false},
			{"cache-control", "private", false},
			{"date", "Mon, 21 Oct 2013 20:13:21 GMT", false},
			{"location", "https://www.example.com", false},
		},
		{
			{":status", "307", false},
			{"cache-control", "private", false},
			{"date", "Mon, 21 Oct 2013 20:13:21 GMT", false},
			{"location", "https://www.example.com", false},
		},
		{
			{":status", "200", false},
			{"cache-control", "private", false},
			{"date", "Mon, 21 Oct 2013 20:13:22 GMT", false},
			{"location", "https://www.example.com", false},
			{"content-encoding", "gzip", false},
			{"set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", false},
		},
	}
	dynamicTable := [][]Header{
		{
			{"location", "https://www.example.com", false},
			{"date", "Mon, 21 Oct 2013 20:13:21 GMT", false},
			{"cache-control", "private", false},
			{":status", "302", false},
		},
		{
			{":status", "307", false},
			{"location", "https://www.example.com", false},
			{"date", "Mon, 21 Oct 2013 20:13:21 GMT", false},
			{"cache-control", "private", false},
		},
		{
			{"set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", false},
			{"content-encoding", "gzip", false},
			{"date", "Mon, 21 Oct 2013 20:13:22 GMT", false},
		},
	}

	testHeaderEncoding(t, encodedHexValues, headers, dynamicTable, 256, true, true)
}

func TestDecodeWithDynamicTableEvictionsHuffman(t *testing.T) {
	encodedHexValues := []string{
		"488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
		"4883640effc1c0bf",
		"88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
	}
	expected := [][]Header{
		{
			{":status", "302", false},
			{"cache-control", "private", false},
			{"date", "Mon, 21 Oct 2013 20:13:21 GMT", false},
			{"location", "https://www.example.com", false},
		},
		{
			{":status", "307", false},
			{"cache-control", "private", false},
			{"date", "Mon, 21 Oct 2013 20:13:21 GMT", false},
			{"location", "https://www.example.com", false},
		},
		{
			{":status", "200", false},
			{"cache-control", "private", false},
			{"date", "Mon, 21 Oct 2013 20:13:22 GMT", false},
			{"location", "https://www.example.com", false},
			{"content-encoding", "gzip", false},
			{"set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", false},
		},
	}
	dynamicTable := [][]Header{
		{
			{"location", "https://www.example.com", false},
			{"date", "Mon, 21 Oct 2013 20:13:21 GMT", false},
			{"cache-control", "private", false},
			{":status", "302", false},
		},
		{
			{":status", "307", false},
			{"location", "https://www.example.com", false},
			{"date", "Mon, 21 Oct 2013 20:13:21 GMT", false},
			{"cache-control", "private", false},
		},
		{
			{"set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", false},
			{"content-encoding", "gzip", false},
			{"date", "Mon, 21 Oct 2013 20:13:22 GMT", false},
		},
	}

	testHeaderParsing(t, encodedHexValues, expected, dynamicTable, 256)
}

func TestDecodeWithDynamicTableEvictionsNoHuffman(t *testing.T) {
	encodedHexValues := []string{
		"4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
		"4803333037c1c0bf",
		"88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
	}
	expected := [][]Header{
		{
			{":status", "302", false},
			{"cache-control", "private", false},
			{"date", "Mon, 21 Oct 2013 20:13:21 GMT", false},
			{"location", "https://www.example.com", false},
		},
		{
			{":status", "307", false},
			{"cache-control", "private", false},
			{"date", "Mon, 21 Oct 2013 20:13:21 GMT", false},
			{"location", "https://www.example.com", false},
		},
		{
			{":status", "200", false},
			{"cache-control", "private", false},
			{"date", "Mon, 21 Oct 2013 20:13:22 GMT", false},
			{"location", "https://www.example.com", false},
			{"content-encoding", "gzip", false},
			{"set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", false},
		},
	}
	dynamicTable := [][]Header{
		{
			{"location", "https://www.example.com", false},
			{"date", "Mon, 21 Oct 2013 20:13:21 GMT", false},
			{"cache-control", "private", false},
			{":status", "302", false},
		},
		{
			{":status", "307", false},
			{"location", "https://www.example.com", false},
			{"date", "Mon, 21 Oct 2013 20:13:21 GMT", false},
			{"cache-control", "private", false},
		},
		{
			{"set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", false},
			{"content-encoding", "gzip", false},
			{"date", "Mon, 21 Oct 2013 20:13:22 GMT", false},
		},
	}

	testHeaderParsing(t, encodedHexValues, expected, dynamicTable, 256)
}

func TestDynamicTableResizingEncoding(t *testing.T) {
	encoder := NewEncoder(64 + 4)
	encoder.addNewDynamicEntry("a", "b")
	encoder.addNewDynamicEntry("b", "c")
	assert.Equal(t, []Header{{"b", "c", false}, {"a", "b", false}}, encoder.dynamicTable)
	encoder.SetDynamicTableMaxSize(63)
	encoded, err := encoder.Encode([]Header{{"b", "c", false}})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, []byte{0x3f, 0x20}, encoded[:2])
	_, _, decoded, err := decodeInteger(encoded, 5, DefaultMaxIntegerValue, DefaultMaxIntegerEncodedLength)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 63, decoded)
	assert.Equal(t, byte(0xbe), encoded[2])
	assert.Equal(t, []Header{{"b", "c", false}}, encoder.dynamicTable)
}

func TestDynamicTableResizing(t *testing.T) {
	decoder := NewDecoder(64 + 4)
	decoder.addNewDynamicEntry("a", "b")
	decoder.addNewDynamicEntry("b", "c")
	assert.Equal(t, []Header{{"b", "c", false}, {"a", "b", false}}, decoder.dynamicTable)
	_, err := decoder.Decode([]byte{63, 3})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, []Header{{"b", "c", false}}, decoder.dynamicTable)
}

func TestDynamicTableEntryBiggerThanTable(t *testing.T) {
	decoder := NewDecoder(32 + 12)
	decoder.addNewDynamicEntry("a", "b")
	decoder.addNewDynamicEntry("aafadslkjasfdkljasfkdjlajklsfdfajklsfdjkladsfjklasjklfdf", "adfsljasfdkjlsdalkfajklsdfjkalsfdjalsdfjalksdfjaldskfjlsjk")
	assert.Equal(t, []Header{}, decoder.dynamicTable)
}
