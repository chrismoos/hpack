package hpack

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHuffmanEncoding(t *testing.T) {
	items := [][2]string{
		{"a8eb10649cbf", "no-cache"},
		{"f1e3c2e5f23a6ba0ab90f4ff", "www.example.com"},
		{"25a849e95ba97d7f", "custom-key"},
		{"25a849e95bb8e8b4bf", "custom-value"},
		{"6402", "302"},
	}

	for _, item := range items {
		encodedHex := []byte(item[0])
		encoded := make([]byte, len(encodedHex)/2)
		_, err := hex.Decode(encoded, encodedHex)
		if err != nil {
			t.Error(err)
		}
		data := HuffmanEncode([]byte(item[1]))
		if err != nil {
			t.Error(err)
		}
		assert.Equal(t, encoded, data)
	}

}

func TestHuffmanDecoding(t *testing.T) {
	items := [][2]string{
		{"a8eb10649cbf", "no-cache"},
		{"f1e3c2e5f23a6ba0ab90f4ff", "www.example.com"},
		{"25a849e95ba97d7f", "custom-key"},
		{"25a849e95bb8e8b4bf", "custom-value"},
	}

	for _, item := range items {
		encodedHex := []byte(item[0])
		encoded := make([]byte, len(encodedHex)/2)
		_, err := hex.Decode(encoded, encodedHex)
		if err != nil {
			t.Error(err)
		}
		decoded, err := HuffmanDecode(encoded)
		if err != nil {
			t.Error(err)
		}
		assert.Equal(t, item[1], string(decoded))
	}

}
