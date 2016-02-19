# HPACK library

[![Build Status](https://travis-ci.org/chrismoos/hpack.svg?branch=master)](https://travis-ci.org/chrismoos/hpack) [![godoc](https://godoc.org/github.com/chrismoos/hpack?status.svg)](https://godoc.org/github.com/chrismoos/hpack)

This library implements [RFC7541](https://tools.ietf.org/html/rfc7541), **HPACK: Header Compression for HTTP/2**, which includes:

* Primitive Type Representations
    * Variable integer sizes (with prefix lengths)
    * String literals (incl. Huffman decoding)
* Static & Dynamic indexes
* Dynamic Table evictions
* Header block parsing

## Usage

Most users of this library will be implementing HTTP/2.

    decoder := hpack.NewDecoder(negotiatedDynamicTableSizeMax)
    headerBlock := recvHeaderBlockAndContinuations()
    headers, err := decoder.Decode(headerBlock)

The `Decode` function expects a complete header block. HTTP/2 specifies that a header block can be split across multiple frames, in a **HEADER** or **PUSH_PROMISE** frame plus optional **CONTINUATION** frames.

Users should concatenate the header block fragments together and only call `ParseHeadersBlock` when a frame with the **END_HEADERS** flag is received.

## Development

### Generating Huffman lookup tables

The lookup tables are code generated from the Huffman codes in the HPACK specification. This ensures the lookup tables are available at runtime with no initialization required.

Run the following command to generate the lookup tables used for Huffman decoding:

    go run cmd/generate_huffman_tables/main.go | gofmt > huffman_tables.go

## License

    Copyright 2016 Chris Moos

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
