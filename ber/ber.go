package ber

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unsafe"
)

// Errors
var (
	ErrBufferOverflow    = errors.New("buffer overflow")
	ErrInvalidLength     = errors.New("invalid length")
	ErrInvalidIndefinite = errors.New("invalid indefinite length")
	ErrMaxDepthExceeded  = errors.New("maximum depth exceeded")
)

// ItuObjectIdentifier represents an ITU-T Object Identifier
type ItuObjectIdentifier struct {
	Arc      [10]uint32
	ArcCount int
}

// Asn1PrimitiveValue represents an ASN.1 primitive value
type Asn1PrimitiveValue struct {
	Size    uint8
	MaxSize uint8
	Octets  []byte
}

// NewAsn1PrimitiveValue creates a new Asn1PrimitiveValue with the specified max size
func NewAsn1PrimitiveValue(maxSize int) *Asn1PrimitiveValue {
	if maxSize <= 0 {
		return nil
	}
	return &Asn1PrimitiveValue{
		Size:    1,
		MaxSize: uint8(maxSize),
		Octets:  make([]byte, maxSize),
	}
}

// Clone creates a copy of the Asn1PrimitiveValue
func (v *Asn1PrimitiveValue) Clone() *Asn1PrimitiveValue {
	if v == nil {
		return nil
	}
	clone := &Asn1PrimitiveValue{
		Size:    v.Size,
		MaxSize: v.MaxSize,
		Octets:  make([]byte, len(v.Octets)),
	}
	copy(clone.Octets, v.Octets)
	return clone
}

// Compare compares two Asn1PrimitiveValue instances
func (v *Asn1PrimitiveValue) Compare(other *Asn1PrimitiveValue) bool {
	if v == nil || other == nil {
		return v == other
	}
	if v.Size != other.Size {
		return false
	}
	if len(v.Octets) < int(v.Size) || len(other.Octets) < int(other.Size) {
		return false
	}
	for i := 0; i < int(v.Size); i++ {
		if v.Octets[i] != other.Octets[i] {
			return false
		}
	}
	return true
}

// Decoder functions

const maxDepth = 50

// DecodeLength decodes a BER length field from the buffer
// Returns the new buffer position and the decoded length, or an error
func DecodeLength(buffer []byte, bufPos, maxBufPos int) (newPos int, length int, err error) {
	return decodeLengthRecursive(buffer, bufPos, maxBufPos, 0, maxDepth)
}

func decodeLengthRecursive(buffer []byte, bufPos, maxBufPos, depth, maxDepth int) (newPos int, length int, err error) {
	if bufPos >= maxBufPos {
		return -1, 0, ErrBufferOverflow
	}

	len1 := buffer[bufPos]
	bufPos++

	if len1&0x80 != 0 {
		lenLength := int(len1 & 0x7f)

		if lenLength == 0 {
			// indefinite length form
			indefLength, err := getIndefiniteLength(buffer, bufPos, maxBufPos, depth, maxDepth)
			if err != nil {
				return -1, 0, err
			}
			length = indefLength
		} else {
			length = 0
			for i := 0; i < lenLength; i++ {
				if bufPos >= maxBufPos {
					return -1, 0, ErrBufferOverflow
				}
				if bufPos+length > maxBufPos {
					return -1, 0, ErrBufferOverflow
				}
				length = (length << 8) | int(buffer[bufPos])
				bufPos++
			}
		}
	} else {
		length = int(len1)
	}

	if length < 0 {
		return -1, 0, ErrInvalidLength
	}

	if bufPos+length > maxBufPos {
		return -1, 0, ErrBufferOverflow
	}

	return bufPos, length, nil
}

func getIndefiniteLength(buffer []byte, bufPos, maxBufPos, depth, maxDepth int) (int, error) {
	depth++
	if depth > maxDepth {
		return -1, ErrMaxDepthExceeded
	}

	length := 0
	for bufPos < maxBufPos {
		if bufPos+1 < maxBufPos && buffer[bufPos] == 0 && buffer[bufPos+1] == 0 {
			return length + 2, nil
		}

		length++

		if (buffer[bufPos] & 0x1f) == 0x1f {
			// handle extended tags
			bufPos++
			length++
		}

		subLength := -1
		newBufPos, subLength, err := decodeLengthRecursive(buffer, bufPos, maxBufPos, depth, maxDepth)
		if err != nil {
			return -1, err
		}

		length += subLength + (newBufPos - bufPos)
		bufPos = newBufPos + subLength
	}

	return -1, ErrInvalidIndefinite
}

// DecodeString decodes a BER string from the buffer
func DecodeString(buffer []byte, strlen, bufPos, maxBufPos int) (string, error) {
	if maxBufPos-bufPos < 0 {
		return "", ErrBufferOverflow
	}
	if bufPos+strlen > maxBufPos {
		return "", ErrBufferOverflow
	}
	return string(buffer[bufPos : bufPos+strlen]), nil
}

// DecodeUint32 decodes a BER unsigned 32-bit integer from the buffer
func DecodeUint32(buffer []byte, intLen, bufPos int) uint32 {
	value := uint32(0)
	for i := 0; i < intLen; i++ {
		value = (value << 8) | uint32(buffer[bufPos+i])
	}
	return value
}

// DecodeInt32 decodes a BER signed 32-bit integer from the buffer
func DecodeInt32(buffer []byte, intLen, bufPos int) int32 {
	var value int32
	isNegative := (buffer[bufPos] & 0x80) == 0x80

	if isNegative {
		value = -1
	} else {
		value = 0
	}

	for i := 0; i < intLen; i++ {
		value = (value << 8) | int32(buffer[bufPos+i])
	}

	return value
}

// DecodeFloat decodes a BER float (32-bit) from the buffer
func DecodeFloat(buffer []byte, bufPos int) float32 {
	bufPos++ // skip exponentWidth field

	var value float32
	valueBuf := (*[4]byte)(unsafe.Pointer(&value))

	// Handle endianness
	if isLittleEndian() {
		for i := 3; i >= 0; i-- {
			valueBuf[i] = buffer[bufPos]
			bufPos++
		}
	} else {
		for i := 0; i < 4; i++ {
			valueBuf[i] = buffer[bufPos]
			bufPos++
		}
	}

	return value
}

// DecodeDouble decodes a BER double (64-bit) from the buffer
func DecodeDouble(buffer []byte, bufPos int) float64 {
	bufPos++ // skip exponentWidth field

	var value float64
	valueBuf := (*[8]byte)(unsafe.Pointer(&value))

	// Handle endianness
	if isLittleEndian() {
		for i := 7; i >= 0; i-- {
			valueBuf[i] = buffer[bufPos]
			bufPos++
		}
	} else {
		for i := 0; i < 8; i++ {
			valueBuf[i] = buffer[bufPos]
			bufPos++
		}
	}

	return value
}

// DecodeBoolean decodes a BER boolean from the buffer
func DecodeBoolean(buffer []byte, bufPos int) bool {
	return buffer[bufPos] != 0
}

// DecodeOID decodes a BER Object Identifier from the buffer
func DecodeOID(buffer []byte, bufPos, length int, oid *ItuObjectIdentifier) {
	startPos := bufPos
	currentArc := 0

	// clear all arcs
	for i := 0; i < 10; i++ {
		oid.Arc[i] = 0
	}

	// parse first two arcs
	if length > 0 {
		oid.Arc[0] = uint32(buffer[bufPos] / 40)
		oid.Arc[1] = uint32(buffer[bufPos] % 40)
		currentArc = 2
		bufPos++
	}

	// parse remaining arcs
	for (bufPos-startPos < length) && (currentArc < 10) {
		oid.Arc[currentArc] = oid.Arc[currentArc] << 7

		if buffer[bufPos] < 0x80 {
			oid.Arc[currentArc] += uint32(buffer[bufPos])
			currentArc++
		} else {
			oid.Arc[currentArc] += uint32(buffer[bufPos] & 0x7f)
		}

		bufPos++
	}

	oid.ArcCount = currentArc
}

// Encoder functions

// EncodeLength encodes a length value in BER format
// Returns the new buffer position
func EncodeLength(length uint32, buffer []byte, bufPos int) int {
	if length < 128 {
		buffer[bufPos] = byte(length)
		bufPos++
	} else if length < 256 {
		buffer[bufPos] = 0x81
		bufPos++
		buffer[bufPos] = byte(length)
		bufPos++
	} else if length < 65536 {
		buffer[bufPos] = 0x82
		bufPos++
		buffer[bufPos] = byte(length / 256)
		bufPos++
		buffer[bufPos] = byte(length % 256)
		bufPos++
	} else {
		buffer[bufPos] = 0x83
		bufPos++
		buffer[bufPos] = byte(length / 0x10000)
		bufPos++
		buffer[bufPos] = byte((length & 0xffff) / 0x100)
		bufPos++
		buffer[bufPos] = byte(length % 256)
		bufPos++
	}
	return bufPos
}

// EncodeTL encodes a Tag and Length in BER format
func EncodeTL(tag byte, length uint32, buffer []byte, bufPos int) int {
	buffer[bufPos] = tag
	bufPos++
	return EncodeLength(length, buffer, bufPos)
}

// EncodeBoolean encodes a boolean value with tag in BER format
func EncodeBoolean(tag byte, value bool, buffer []byte, bufPos int) int {
	buffer[bufPos] = tag
	bufPos++
	buffer[bufPos] = 1
	bufPos++
	if value {
		buffer[bufPos] = 0x01
	} else {
		buffer[bufPos] = 0x00
	}
	bufPos++
	return bufPos
}

// EncodeStringWithTag encodes a string with tag in BER format
func EncodeStringWithTag(tag byte, str string, buffer []byte, bufPos int) int {
	buffer[bufPos] = tag
	bufPos++

	if str != "" {
		length := uint32(len(str))
		bufPos = EncodeLength(length, buffer, bufPos)
		for i := 0; i < len(str); i++ {
			buffer[bufPos] = str[i]
			bufPos++
		}
	} else {
		buffer[bufPos] = 0
		bufPos++
	}

	return bufPos
}

// EncodeOctetString encodes an octet string with tag in BER format
func EncodeOctetString(tag byte, octetString []byte, buffer []byte, bufPos int) int {
	buffer[bufPos] = tag
	bufPos++

	octetStringSize := uint32(len(octetString))
	bufPos = EncodeLength(octetStringSize, buffer, bufPos)

	for i := 0; i < len(octetString); i++ {
		buffer[bufPos] = octetString[i]
		bufPos++
	}

	return bufPos
}

// EncodeAsn1PrimitiveValue encodes an Asn1PrimitiveValue with tag in BER format
func EncodeAsn1PrimitiveValue(tag byte, value *Asn1PrimitiveValue, buffer []byte, bufPos int) int {
	buffer[bufPos] = tag
	bufPos++

	bufPos = EncodeLength(uint32(value.Size), buffer, bufPos)

	for i := 0; i < int(value.Size); i++ {
		buffer[bufPos] = value.Octets[i]
		bufPos++
	}

	return bufPos
}

// EncodeBitString encodes a bit string with tag in BER format
func EncodeBitString(tag byte, bitStringSize int, bitString []byte, buffer []byte, bufPos int) int {
	buffer[bufPos] = tag
	bufPos++

	byteSize := bitStringSize / 8
	if bitStringSize%8 != 0 {
		byteSize++
	}

	padding := (byteSize * 8) - bitStringSize

	bufPos = EncodeLength(uint32(byteSize+1), buffer, bufPos)

	buffer[bufPos] = byte(padding)
	bufPos++

	for i := 0; i < byteSize; i++ {
		buffer[bufPos] = bitString[i]
		bufPos++
	}

	// Apply padding mask
	paddingMask := byte(0)
	for i := 0; i < padding; i++ {
		paddingMask += (1 << i)
	}
	paddingMask = ^paddingMask

	buffer[bufPos-1] = buffer[bufPos-1] & paddingMask

	return bufPos
}

// RevertByteOrder reverses the byte order of the given slice
func RevertByteOrder(octets []byte) {
	size := len(octets)
	for i := 0; i < size/2; i++ {
		temp := octets[i]
		octets[i] = octets[size-1-i]
		octets[size-1-i] = temp
	}
}

// CompressInteger removes leading zero bytes or leading 0xFF bytes from an integer
// Returns the new size
func CompressInteger(integer []byte) int {
	originalSize := len(integer)
	integerEnd := originalSize - 1
	bytePosition := 0

	for bytePosition < integerEnd {
		if integer[bytePosition] == 0x00 {
			if (integer[bytePosition+1] & 0x80) == 0 {
				bytePosition++
				continue
			}
		} else if integer[bytePosition] == 0xff {
			if (integer[bytePosition+1] & 0x80) == 0x80 {
				bytePosition++
				continue
			}
		}
		break
	}

	bytesToDelete := bytePosition
	newSize := originalSize

	if bytesToDelete > 0 {
		newSize -= bytesToDelete
		for i := 0; i < newSize; i++ {
			integer[i] = integer[bytePosition]
			bytePosition++
		}
	}

	return newSize
}

// EncodeUInt32 encodes an unsigned 32-bit integer in BER format
func EncodeUInt32(value uint32, buffer []byte, bufPos int) int {
	valueArray := make([]byte, 4)
	binary.BigEndian.PutUint32(valueArray, value)

	valueBuffer := make([]byte, 5)
	valueBuffer[0] = 0
	copy(valueBuffer[1:], valueArray)

	if isLittleEndian() {
		RevertByteOrder(valueBuffer[1:])
	}

	size := CompressInteger(valueBuffer)

	for i := 0; i < size; i++ {
		buffer[bufPos] = valueBuffer[i]
		bufPos++
	}

	return bufPos
}

// EncodeInt32 encodes a signed 32-bit integer in BER format
func EncodeInt32(value int32, buffer []byte, bufPos int) int {
	valueArray := make([]byte, 4)
	binary.BigEndian.PutUint32(valueArray, uint32(value))

	valueBuffer := make([]byte, 4)
	copy(valueBuffer, valueArray)

	if isLittleEndian() {
		RevertByteOrder(valueBuffer)
	}

	size := CompressInteger(valueBuffer)

	for i := 0; i < size; i++ {
		buffer[bufPos] = valueBuffer[i]
		bufPos++
	}

	return bufPos
}

// EncodeUInt32WithTL encodes an unsigned 32-bit integer with tag and length in BER format
func EncodeUInt32WithTL(tag byte, value uint32, buffer []byte, bufPos int) int {
	valueArray := make([]byte, 4)
	binary.BigEndian.PutUint32(valueArray, value)

	valueBuffer := make([]byte, 5)
	valueBuffer[0] = 0
	copy(valueBuffer[1:], valueArray)

	if isLittleEndian() {
		RevertByteOrder(valueBuffer[1:])
	}

	size := CompressInteger(valueBuffer)

	buffer[bufPos] = tag
	bufPos++
	buffer[bufPos] = byte(size)
	bufPos++

	for i := 0; i < size; i++ {
		buffer[bufPos] = valueBuffer[i]
		bufPos++
	}

	return bufPos
}

// EncodeFloat encodes a float value in BER format
func EncodeFloat(floatValue []byte, formatWidth, exponentWidth byte, buffer []byte, bufPos int) int {
	valueBuffer := buffer[bufPos:]
	byteSize := int(formatWidth / 8)

	valueBuffer[0] = exponentWidth

	for i := 0; i < byteSize; i++ {
		valueBuffer[i+1] = floatValue[i]
	}

	if isLittleEndian() {
		RevertByteOrder(valueBuffer[1 : byteSize+1])
	}

	return bufPos + 1 + byteSize
}

// Size determination functions

// UInt32DetermineEncodedSize determines the encoded size of an unsigned 32-bit integer
func UInt32DetermineEncodedSize(value uint32) int {
	valueArray := make([]byte, 4)
	binary.BigEndian.PutUint32(valueArray, value)

	valueBuffer := make([]byte, 5)
	valueBuffer[0] = 0
	copy(valueBuffer[1:], valueArray)

	if isLittleEndian() {
		RevertByteOrder(valueBuffer[1:])
	}

	return CompressInteger(valueBuffer)
}

// Int32DetermineEncodedSize determines the encoded size of a signed 32-bit integer
func Int32DetermineEncodedSize(value int32) int {
	valueArray := make([]byte, 4)
	binary.BigEndian.PutUint32(valueArray, uint32(value))

	valueBuffer := make([]byte, 5)
	valueBuffer[0] = 0
	copy(valueBuffer[1:], valueArray)

	if isLittleEndian() {
		RevertByteOrder(valueBuffer[1:])
	}

	return CompressInteger(valueBuffer)
}

// DetermineLengthSize determines the size needed to encode a length value
func DetermineLengthSize(length uint32) int {
	if length < 128 {
		return 1
	}
	if length < 256 {
		return 2
	}
	if length < 65536 {
		return 3
	}
	return 4
}

// DetermineEncodedStringSize determines the encoded size of a string
func DetermineEncodedStringSize(str string) int {
	if str != "" {
		size := 1 // tag
		length := len(str)
		size += DetermineLengthSize(uint32(length))
		size += length
		return size
	}
	return 2 // tag + length (0)
}

// DetermineEncodedBitStringSize determines the encoded size of a bit string
func DetermineEncodedBitStringSize(bitStringSize int) int {
	size := 2 // for tag and padding

	byteSize := bitStringSize / 8
	if bitStringSize%8 != 0 {
		byteSize++
	}

	size += DetermineLengthSize(uint32(byteSize))
	size += byteSize

	return size
}

// EncodeOIDToBuffer encodes an OID string to a buffer
func EncodeOIDToBuffer(oidString string, buffer []byte, maxBufLen int) (int, error) {
	encodedBytes := 0

	// Find separator
	sepChar := '.'
	separator := strings.IndexByte(oidString, '.')
	if separator == -1 {
		sepChar = ','
		separator = strings.IndexByte(oidString, ',')
	}
	if separator == -1 {
		sepChar = ' '
		separator = strings.IndexByte(oidString, ' ')
	}
	if separator == -1 {
		return 0, errors.New("invalid OID format")
	}

	x, err := strconv.Atoi(oidString[:separator])
	if err != nil {
		return 0, fmt.Errorf("invalid OID: %w", err)
	}

	nextSep := strings.IndexByte(oidString[separator+1:], byte(sepChar))
	var yStr string
	if nextSep == -1 {
		yStr = oidString[separator+1:]
	} else {
		yStr = oidString[separator+1 : separator+1+nextSep]
	}

	y, err := strconv.Atoi(yStr)
	if err != nil {
		return 0, fmt.Errorf("invalid OID: %w", err)
	}

	val := x*40 + y

	if encodedBytes >= maxBufLen {
		return 0, ErrBufferOverflow
	}
	buffer[encodedBytes] = byte(val)
	encodedBytes++

	remaining := oidString[separator+1:]
	if nextSep != -1 {
		remaining = remaining[nextSep+1:]
	}

	for {
		separator = strings.IndexByte(remaining, byte(sepChar))
		if separator == -1 {
			break
		}

		valStr := remaining[:separator]
		val, err := strconv.Atoi(valStr)
		if err != nil {
			return 0, fmt.Errorf("invalid OID: %w", err)
		}

		if val == 0 {
			if encodedBytes >= maxBufLen {
				return 0, ErrBufferOverflow
			}
			buffer[encodedBytes] = 0
			encodedBytes++
		} else {
			requiredBytes := 0
			val2 := val

			for val2 > 0 {
				requiredBytes++
				val2 = val2 >> 7
			}

			for requiredBytes > 0 {
				val2 = val >> (7 * (requiredBytes - 1))
				val2 = val2 & 0x7f

				if requiredBytes > 1 {
					val2 += 128
				}

				if encodedBytes >= maxBufLen {
					return 0, ErrBufferOverflow
				}

				buffer[encodedBytes] = byte(val2)
				encodedBytes++

				requiredBytes--
			}
		}

		remaining = remaining[separator+1:]
	}

	// Handle last value
	if remaining != "" {
		val, err := strconv.Atoi(remaining)
		if err != nil {
			return 0, fmt.Errorf("invalid OID: %w", err)
		}

		if val == 0 {
			if encodedBytes >= maxBufLen {
				return 0, ErrBufferOverflow
			}
			buffer[encodedBytes] = 0
			encodedBytes++
		} else {
			requiredBytes := 0
			val2 := val

			for val2 > 0 {
				requiredBytes++
				val2 = val2 >> 7
			}

			for requiredBytes > 0 {
				val2 = val >> (7 * (requiredBytes - 1))
				val2 = val2 & 0x7f

				if requiredBytes > 1 {
					val2 += 128
				}

				if encodedBytes >= maxBufLen {
					return 0, ErrBufferOverflow
				}

				buffer[encodedBytes] = byte(val2)
				encodedBytes++

				requiredBytes--
			}
		}
	}

	return encodedBytes, nil
}

// Helper functions

func isLittleEndian() bool {
	var x uint32 = 0x01020304
	return *(*byte)(unsafe.Pointer(&x)) == 0x04
}
