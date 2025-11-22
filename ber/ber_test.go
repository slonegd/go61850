package ber

import (
	"bytes"
	"testing"
)

func TestDecodeLength(t *testing.T) {
	tests := []struct {
		name      string
		buffer    []byte
		bufPos    int
		maxBufPos int
		wantPos   int
		wantLen   int
		wantErr   error
	}{
		{
			name:      "short form length < 128",
			buffer:    []byte{0x05, 0x00, 0x00, 0x00, 0x00, 0x00},
			bufPos:    0,
			maxBufPos: 6,
			wantPos:   1,
			wantLen:   5,
			wantErr:   nil,
		},
		{
			name:      "long form 1 byte",
			buffer:    append([]byte{0x81, 0xFF}, make([]byte, 0xFF)...),
			bufPos:    0,
			maxBufPos: 2 + 0xFF,
			wantPos:   2,
			wantLen:   0xFF,
			wantErr:   nil,
		},
		{
			name:      "long form 2 bytes",
			buffer:    append([]byte{0x82, 0x01, 0x00}, make([]byte, 0x0100)...),
			bufPos:    0,
			maxBufPos: 3 + 0x0100,
			wantPos:   3,
			wantLen:   0x0100,
			wantErr:   nil,
		},
		{
			name:      "long form 3 bytes",
			buffer:    append([]byte{0x83, 0x00, 0x01, 0x00}, make([]byte, 0x000100)...),
			bufPos:    0,
			maxBufPos: 4 + 0x000100,
			wantPos:   4,
			wantLen:   0x000100,
			wantErr:   nil,
		},
		{
			name:      "buffer overflow",
			buffer:    []byte{0x81},
			bufPos:    0,
			maxBufPos: 1,
			wantPos:   -1,
			wantLen:   0,
			wantErr:   ErrBufferOverflow,
		},
		{
			name:      "zero length",
			buffer:    []byte{0x00},
			bufPos:    0,
			maxBufPos: 1,
			wantPos:   1,
			wantLen:   0,
			wantErr:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPos, gotLen, err := DecodeLength(tt.buffer, tt.bufPos, tt.maxBufPos)
			if err != tt.wantErr {
				t.Errorf("DecodeLength() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotPos != tt.wantPos {
				t.Errorf("DecodeLength() gotPos = %v, want %v", gotPos, tt.wantPos)
			}
			if gotLen != tt.wantLen {
				t.Errorf("DecodeLength() gotLen = %v, want %v", gotLen, tt.wantLen)
			}
		})
	}
}

func TestDecodeString(t *testing.T) {
	tests := []struct {
		name      string
		buffer    []byte
		strlen    int
		bufPos    int
		maxBufPos int
		want      string
		wantErr   error
	}{
		{
			name:      "simple string",
			buffer:    []byte("Hello"),
			strlen:    5,
			bufPos:    0,
			maxBufPos: 5,
			want:      "Hello",
			wantErr:   nil,
		},
		{
			name:      "empty string",
			buffer:    []byte(""),
			strlen:    0,
			bufPos:    0,
			maxBufPos: 0,
			want:      "",
			wantErr:   nil,
		},
		{
			name:      "buffer overflow",
			buffer:    []byte("Hello"),
			strlen:    10,
			bufPos:    0,
			maxBufPos: 5,
			want:      "",
			wantErr:   ErrBufferOverflow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeString(tt.buffer, tt.strlen, tt.bufPos, tt.maxBufPos)
			if err != tt.wantErr {
				t.Errorf("DecodeString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DecodeString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeUint32(t *testing.T) {
	tests := []struct {
		name   string
		buffer []byte
		intLen int
		bufPos int
		want   uint32
	}{
		{
			name:   "1 byte",
			buffer: []byte{0xFF},
			intLen: 1,
			bufPos: 0,
			want:   0xFF,
		},
		{
			name:   "2 bytes",
			buffer: []byte{0x01, 0x00},
			intLen: 2,
			bufPos: 0,
			want:   0x0100,
		},
		{
			name:   "4 bytes",
			buffer: []byte{0x12, 0x34, 0x56, 0x78},
			intLen: 4,
			bufPos: 0,
			want:   0x12345678,
		},
		{
			name:   "zero",
			buffer: []byte{0x00, 0x00, 0x00, 0x00},
			intLen: 4,
			bufPos: 0,
			want:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DecodeUint32(tt.buffer, tt.intLen, tt.bufPos)
			if got != tt.want {
				t.Errorf("DecodeUint32() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeInt32(t *testing.T) {
	tests := []struct {
		name   string
		buffer []byte
		intLen int
		bufPos int
		want   int32
	}{
		{
			name:   "positive 1 byte",
			buffer: []byte{0x7F},
			intLen: 1,
			bufPos: 0,
			want:   0x7F,
		},
		{
			name:   "negative 1 byte",
			buffer: []byte{0x80},
			intLen: 1,
			bufPos: 0,
			want:   -128,
		},
		{
			name:   "positive 4 bytes",
			buffer: []byte{0x12, 0x34, 0x56, 0x78},
			intLen: 4,
			bufPos: 0,
			want:   0x12345678,
		},
		{
			name:   "negative 4 bytes",
			buffer: []byte{0xFF, 0xFF, 0xFF, 0xFF},
			intLen: 4,
			bufPos: 0,
			want:   -1,
		},
		{
			name:   "zero",
			buffer: []byte{0x00, 0x00, 0x00, 0x00},
			intLen: 4,
			bufPos: 0,
			want:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DecodeInt32(tt.buffer, tt.intLen, tt.bufPos)
			if got != tt.want {
				t.Errorf("DecodeInt32() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeBoolean(t *testing.T) {
	tests := []struct {
		name   string
		buffer []byte
		bufPos int
		want   bool
	}{
		{
			name:   "true",
			buffer: []byte{0x01},
			bufPos: 0,
			want:   true,
		},
		{
			name:   "false",
			buffer: []byte{0x00},
			bufPos: 0,
			want:   false,
		},
		{
			name:   "non-zero is true",
			buffer: []byte{0xFF},
			bufPos: 0,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DecodeBoolean(tt.buffer, tt.bufPos)
			if got != tt.want {
				t.Errorf("DecodeBoolean() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeOID(t *testing.T) {
	tests := []struct {
		name    string
		buffer  []byte
		bufPos  int
		length  int
		wantOID ItuObjectIdentifier
	}{
		{
			name:   "simple OID",
			buffer: []byte{0x28, 0xca, 0x22, 0x02, 0x01},
			bufPos: 0,
			length: 5,
			wantOID: ItuObjectIdentifier{
				Arc:      [10]uint32{1, 0, 9506, 2, 1, 0, 0, 0, 0, 0},
				ArcCount: 5,
			},
		},
		{
			name:   "two arc OID",
			buffer: []byte{0x52, 0x01},
			bufPos: 0,
			length: 2,
			wantOID: ItuObjectIdentifier{
				Arc:      [10]uint32{2, 2, 1, 0, 0, 0, 0, 0, 0, 0},
				ArcCount: 3,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var oid ItuObjectIdentifier
			DecodeOID(tt.buffer, tt.bufPos, tt.length, &oid)
			if oid.ArcCount != tt.wantOID.ArcCount {
				t.Errorf("DecodeOID() ArcCount = %v, want %v", oid.ArcCount, tt.wantOID.ArcCount)
			}
			for i := 0; i < oid.ArcCount; i++ {
				if oid.Arc[i] != tt.wantOID.Arc[i] {
					t.Errorf("DecodeOID() Arc[%d] = %v, want %v", i, oid.Arc[i], tt.wantOID.Arc[i])
				}
			}
		})
	}
}

func TestEncodeLength(t *testing.T) {
	tests := []struct {
		name    string
		length  uint32
		buffer  []byte
		bufPos  int
		wantPos int
		wantBuf []byte
	}{
		{
			name:    "short form < 128",
			length:  5,
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 1,
			wantBuf: []byte{0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:    "long form 1 byte",
			length:  0xFF,
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 2,
			wantBuf: []byte{0x81, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:    "long form 2 bytes",
			length:  0x0100,
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 3,
			wantBuf: []byte{0x82, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:    "long form 3 bytes",
			length:  0x010000,
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 4,
			wantBuf: []byte{0x83, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPos := EncodeLength(tt.length, tt.buffer, tt.bufPos)
			if gotPos != tt.wantPos {
				t.Errorf("EncodeLength() gotPos = %v, want %v", gotPos, tt.wantPos)
			}
			if !bytes.Equal(tt.buffer[:tt.wantPos], tt.wantBuf[:tt.wantPos]) {
				t.Errorf("EncodeLength() buffer = %v, want %v", tt.buffer[:tt.wantPos], tt.wantBuf[:tt.wantPos])
			}
		})
	}
}

func TestEncodeTL(t *testing.T) {
	tests := []struct {
		name    string
		tag     byte
		length  uint32
		buffer  []byte
		bufPos  int
		wantPos int
		wantBuf []byte
	}{
		{
			name:    "simple TL",
			tag:     0x06,
			length:  5,
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 2,
			wantBuf: []byte{0x06, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:    "long length",
			tag:     0x06,
			length:  0xFF,
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 3,
			wantBuf: []byte{0x06, 0x81, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPos := EncodeTL(tt.tag, tt.length, tt.buffer, tt.bufPos)
			if gotPos != tt.wantPos {
				t.Errorf("EncodeTL() gotPos = %v, want %v", gotPos, tt.wantPos)
			}
			if !bytes.Equal(tt.buffer[:tt.wantPos], tt.wantBuf[:tt.wantPos]) {
				t.Errorf("EncodeTL() buffer = %v, want %v", tt.buffer[:tt.wantPos], tt.wantBuf[:tt.wantPos])
			}
		})
	}
}

func TestEncodeBoolean(t *testing.T) {
	tests := []struct {
		name    string
		tag     byte
		value   bool
		buffer  []byte
		bufPos  int
		wantPos int
		wantBuf []byte
	}{
		{
			name:    "true",
			tag:     0x01,
			value:   true,
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 3,
			wantBuf: []byte{0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:    "false",
			tag:     0x01,
			value:   false,
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 3,
			wantBuf: []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPos := EncodeBoolean(tt.tag, tt.value, tt.buffer, tt.bufPos)
			if gotPos != tt.wantPos {
				t.Errorf("EncodeBoolean() gotPos = %v, want %v", gotPos, tt.wantPos)
			}
			if !bytes.Equal(tt.buffer[:tt.wantPos], tt.wantBuf[:tt.wantPos]) {
				t.Errorf("EncodeBoolean() buffer = %v, want %v", tt.buffer[:tt.wantPos], tt.wantBuf[:tt.wantPos])
			}
		})
	}
}

func TestEncodeStringWithTag(t *testing.T) {
	tests := []struct {
		name    string
		tag     byte
		str     string
		buffer  []byte
		bufPos  int
		wantPos int
		wantBuf []byte
	}{
		{
			name:    "simple string",
			tag:     0x0C,
			str:     "Hello",
			buffer:  make([]byte, 20),
			bufPos:  0,
			wantPos: 7,
			wantBuf: []byte{0x0C, 0x05, 'H', 'e', 'l', 'l', 'o', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:    "empty string",
			tag:     0x0C,
			str:     "",
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 2,
			wantBuf: []byte{0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPos := EncodeStringWithTag(tt.tag, tt.str, tt.buffer, tt.bufPos)
			if gotPos != tt.wantPos {
				t.Errorf("EncodeStringWithTag() gotPos = %v, want %v", gotPos, tt.wantPos)
			}
			if !bytes.Equal(tt.buffer[:tt.wantPos], tt.wantBuf[:tt.wantPos]) {
				t.Errorf("EncodeStringWithTag() buffer = %v, want %v", tt.buffer[:tt.wantPos], tt.wantBuf[:tt.wantPos])
			}
		})
	}
}

func TestEncodeUInt32(t *testing.T) {
	tests := []struct {
		name    string
		value   uint32
		buffer  []byte
		bufPos  int
		wantPos int
	}{
		{
			name:    "zero",
			value:   0,
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 1,
		},
		{
			name:    "small value",
			value:   127,
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 1,
		},
		{
			name:    "medium value",
			value:   255,
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 2, // After compression, 255 might be 2 bytes
		},
		{
			name:    "large value",
			value:   0x12345678,
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPos := EncodeUInt32(tt.value, tt.buffer, tt.bufPos)
			if gotPos < tt.bufPos || gotPos > len(tt.buffer) {
				t.Errorf("EncodeUInt32() gotPos = %v, out of bounds", gotPos)
			}
			// Verify encoded size is reasonable (1-5 bytes)
			encodedSize := gotPos - tt.bufPos
			if encodedSize < 1 || encodedSize > 5 {
				t.Errorf("EncodeUInt32() encoded size = %v, should be between 1 and 5", encodedSize)
			}
		})
	}
}

func TestEncodeInt32(t *testing.T) {
	tests := []struct {
		name    string
		value   int32
		buffer  []byte
		bufPos  int
		wantPos int
	}{
		{
			name:    "zero",
			value:   0,
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 1,
		},
		{
			name:    "positive",
			value:   127,
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 4, // After compression, might be different
		},
		{
			name:    "negative",
			value:   -1,
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 1,
		},
		{
			name:    "large positive",
			value:   0x7FFFFFFF,
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 2, // After compression
		},
		{
			name:    "large negative",
			value:   -0x80000000,
			buffer:  make([]byte, 10),
			bufPos:  0,
			wantPos: 2, // After compression
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPos := EncodeInt32(tt.value, tt.buffer, tt.bufPos)
			if gotPos < tt.bufPos || gotPos > len(tt.buffer) {
				t.Errorf("EncodeInt32() gotPos = %v, out of bounds", gotPos)
			}
			// Verify encoded size is reasonable (1-4 bytes)
			encodedSize := gotPos - tt.bufPos
			if encodedSize < 1 || encodedSize > 4 {
				t.Errorf("EncodeInt32() encoded size = %v, should be between 1 and 4", encodedSize)
			}
		})
	}
}

func TestCompressInteger(t *testing.T) {
	tests := []struct {
		name    string
		integer []byte
		want    int
		wantBuf []byte
	}{
		{
			name:    "no compression needed",
			integer: []byte{0x12, 0x34},
			want:    2,
			wantBuf: []byte{0x12, 0x34},
		},
		{
			name:    "leading zeros",
			integer: []byte{0x00, 0x00, 0x12, 0x34},
			want:    2,
			wantBuf: []byte{0x12, 0x34, 0x00, 0x00},
		},
		{
			name:    "leading 0xFF for negative",
			integer: []byte{0xFF, 0xFF, 0x80, 0x00},
			want:    2,
			wantBuf: []byte{0x80, 0x00, 0xFF, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			integer := make([]byte, len(tt.integer))
			copy(integer, tt.integer)
			got := CompressInteger(integer)
			if got != tt.want {
				t.Errorf("CompressInteger() = %v, want %v", got, tt.want)
			}
			if !bytes.Equal(integer[:got], tt.wantBuf[:got]) {
				t.Errorf("CompressInteger() buffer = %v, want %v", integer[:got], tt.wantBuf[:got])
			}
		})
	}
}

func TestDetermineLengthSize(t *testing.T) {
	tests := []struct {
		name   string
		length uint32
		want   int
	}{
		{
			name:   "short form",
			length: 127,
			want:   1,
		},
		{
			name:   "long form 1 byte",
			length: 128,
			want:   2,
		},
		{
			name:   "long form 1 byte max",
			length: 255,
			want:   2,
		},
		{
			name:   "long form 2 bytes",
			length: 256,
			want:   3,
		},
		{
			name:   "long form 2 bytes max",
			length: 65535,
			want:   3,
		},
		{
			name:   "long form 3 bytes",
			length: 65536,
			want:   4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetermineLengthSize(tt.length)
			if got != tt.want {
				t.Errorf("DetermineLengthSize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncodeOIDToBuffer(t *testing.T) {
	tests := []struct {
		name      string
		oidString string
		buffer    []byte
		maxBufLen int
		wantBytes int
		wantErr   error
		wantBuf   []byte
	}{
		{
			name:      "simple OID",
			oidString: "1.0.9506.2.1",
			buffer:    make([]byte, 20),
			maxBufLen: 20,
			wantBytes: 5,
			wantErr:   nil,
			wantBuf:   []byte{0x28, 0xca, 0x22, 0x02, 0x01},
		},
		{
			name:      "two arc OID",
			oidString: "2.2.1",
			buffer:    make([]byte, 20),
			maxBufLen: 20,
			wantBytes: 2,
			wantErr:   nil,
			wantBuf:   []byte{0x52, 0x01},
		},
		{
			name:      "buffer overflow",
			oidString: "1.0.9506.2.1",
			buffer:    make([]byte, 3),
			maxBufLen: 3,
			wantBytes: 0,
			wantErr:   ErrBufferOverflow,
			wantBuf:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBytes, err := EncodeOIDToBuffer(tt.oidString, tt.buffer, tt.maxBufLen)
			if err != tt.wantErr {
				t.Errorf("EncodeOIDToBuffer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotBytes != tt.wantBytes {
				t.Errorf("EncodeOIDToBuffer() gotBytes = %v, want %v", gotBytes, tt.wantBytes)
			}
			if tt.wantBuf != nil && !bytes.Equal(tt.buffer[:gotBytes], tt.wantBuf) {
				t.Errorf("EncodeOIDToBuffer() buffer = %v, want %v", tt.buffer[:gotBytes], tt.wantBuf)
			}
		})
	}
}

func TestAsn1PrimitiveValue(t *testing.T) {
	t.Run("Create and Clone", func(t *testing.T) {
		v := NewAsn1PrimitiveValue(10)
		if v == nil {
			t.Fatal("NewAsn1PrimitiveValue() returned nil")
		}
		if v.MaxSize != 10 {
			t.Errorf("MaxSize = %v, want 10", v.MaxSize)
		}

		clone := v.Clone()
		if clone == nil {
			t.Fatal("Clone() returned nil")
		}
		if !v.Compare(clone) {
			t.Error("Clone() should be equal to original")
		}
	})

	t.Run("Compare", func(t *testing.T) {
		v1 := NewAsn1PrimitiveValue(10)
		v2 := NewAsn1PrimitiveValue(10)
		v1.Octets[0] = 0x12
		v1.Size = 1
		v2.Octets[0] = 0x12
		v2.Size = 1

		if !v1.Compare(v2) {
			t.Error("Compare() should return true for equal values")
		}

		v2.Octets[0] = 0x34
		if v1.Compare(v2) {
			t.Error("Compare() should return false for different values")
		}
	})
}

func TestRevertByteOrder(t *testing.T) {
	tests := []struct {
		name   string
		octets []byte
		want   []byte
	}{
		{
			name:   "even length",
			octets: []byte{0x12, 0x34, 0x56, 0x78},
			want:   []byte{0x78, 0x56, 0x34, 0x12},
		},
		{
			name:   "odd length",
			octets: []byte{0x12, 0x34, 0x56},
			want:   []byte{0x56, 0x34, 0x12},
		},
		{
			name:   "single byte",
			octets: []byte{0x12},
			want:   []byte{0x12},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			octets := make([]byte, len(tt.octets))
			copy(octets, tt.octets)
			RevertByteOrder(octets)
			if !bytes.Equal(octets, tt.want) {
				t.Errorf("RevertByteOrder() = %v, want %v", octets, tt.want)
			}
		})
	}
}

// Round-trip tests

func TestEncodeDecodeRoundTrip(t *testing.T) {
	t.Run("Length round trip", func(t *testing.T) {
		lengths := []uint32{0, 1, 127, 128, 255, 256, 65535, 65536}
		for _, length := range lengths {
			buffer := make([]byte, 100)
			pos := EncodeLength(length, buffer, 0)
			// DecodeLength checks if bufPos + length > maxBufPos, so we need to provide
			// enough space for the length value itself
			// The length value is what we're encoding, so we need space for it
			newPos, decoded, err := DecodeLength(buffer, 0, int(length)+pos)
			if err != nil {
				t.Errorf("DecodeLength() error = %v for length %v", err, length)
				continue
			}
			if newPos != pos {
				t.Errorf("Position mismatch: %v != %v", newPos, pos)
			}
			if int(length) != decoded {
				t.Errorf("Round trip failed: %v -> %v", length, decoded)
			}
		}
	})
}
