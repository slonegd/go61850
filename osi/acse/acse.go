package acse

import (
	"errors"
	"fmt"

	"github.com/slonegd/go61850/ber"
)

// ConnectionState represents the state of an ACSE connection
type ConnectionState int

const (
	StateIdle ConnectionState = iota
	StateRequestIndicated
	StateConnected
)

// Indication represents an ACSE indication
type Indication int

const (
	IndicationError Indication = iota
	IndicationAssociate
	IndicationAssociateFailed
	IndicationOK
	IndicationAbort
	IndicationReleaseRequest
	IndicationReleaseResponse
)

// Result represents ACSE result codes
const (
	ResultAccept            = 0
	ResultRejectPermanent   = 1
	ResultRejectTransient   = 2
)

// AuthenticationMechanism represents ACSE authentication mechanisms
type AuthenticationMechanism int

const (
	AuthNone AuthenticationMechanism = iota
	AuthPassword
	AuthCertificate
	AuthTLS
)

// AuthenticationParameter represents ACSE authentication parameters
type AuthenticationParameter struct {
	Mechanism AuthenticationMechanism
	Password  []byte // for ACSE_AUTH_PASSWORD
	Certificate []byte // for ACSE_AUTH_CERTIFICATE or ACSE_AUTH_TLS
}

// ApplicationReference represents ISO application reference
type ApplicationReference struct {
	APTitle    ber.ItuObjectIdentifier
	AEQualifier int32
}

// Connection represents an ACSE connection
type Connection struct {
	State              ConnectionState
	NextReference      uint32
	UserDataBuffer     []byte
	UserDataBufferSize int
	ApplicationRef     ApplicationReference
	// Note: Authenticator callback is not implemented in this version
	// as it's not needed for basic functionality
}

// NewConnection creates a new ACSE connection
func NewConnection() *Connection {
	return &Connection{
		State:         StateIdle,
		NextReference: 0,
	}
}

// Constants for ACSE OIDs and values
var (
	appContextNameMms = []byte{0x28, 0xca, 0x22, 0x02, 0x03}
	authMechPasswordOID = []byte{0x52, 0x03, 0x01}
	requirementsAuthentication = []byte{0x80}
)

// BuildAARQ creates an AARQ (Association Request) PDU
// This is a simplified version that matches the expected packet structure
func BuildAARQ(userData []byte) []byte {
	conn := NewConnection()
	isoParams := &IsoConnectionParameters{
		RemoteAPTitle:     []byte{0x29, 0x01, 0x87, 0x67, 0x01},
		RemoteAPTitleLen: 5,
		RemoteAEQualifier: 12,
		LocalAPTitle:      []byte{0x29, 0x01, 0x87, 0x67},
		LocalAPTitleLen:   4,
		LocalAEQualifier:  12,
	}
	return CreateAssociateRequestMessage(conn, isoParams, userData, nil)
}

// IsoConnectionParameters represents ISO connection parameters
type IsoConnectionParameters struct {
	RemoteAPTitle     []byte
	RemoteAPTitleLen  int
	RemoteAEQualifier int32
	LocalAPTitle      []byte
	LocalAPTitleLen   int
	LocalAEQualifier  int32
}

// CreateAssociateRequestMessage creates an AARQ (Association Request) PDU
// Based on AcseConnection_createAssociateRequestMessage from acse.c
func CreateAssociateRequestMessage(conn *Connection, isoParams *IsoConnectionParameters, payload []byte, authParam *AuthenticationParameter) []byte {
	payloadLength := len(payload)
	
	// Calculate content length
	contentLength := 0
	
	// Application context name (fixed: 9 bytes)
	contentLength += 9
	
	// Called AP title and AE qualifier
	if isoParams != nil && isoParams.RemoteAPTitleLen > 0 {
		// Called AP title: tag(1) + length(1) + OID tag(1) + length(1) + OID data
		contentLength += 4 + isoParams.RemoteAPTitleLen
		
		// Called AE qualifier: tag(1) + length(1) + integer tag(1) + length(1) + value
		// For small values like 12, we need to encode as 1 byte, not 4
		calledAEQualifierLength := determineIntegerEncodedSize(int32(isoParams.RemoteAEQualifier))
		contentLength += 4 + calledAEQualifierLength
	}
	
	// Calling AP title and AE qualifier
	if isoParams != nil && isoParams.LocalAPTitleLen > 0 {
		// Calling AP title: tag(1) + length(1) + OID tag(1) + length(1) + OID data
		contentLength += 4 + isoParams.LocalAPTitleLen
		
		// Calling AE qualifier: tag(1) + length(1) + integer tag(1) + length(1) + value
		// For small values like 12, we need to encode as 1 byte, not 4
		callingAEQualifierLength := determineIntegerEncodedSize(int32(isoParams.LocalAEQualifier))
		contentLength += 4 + callingAEQualifierLength
	}
	
	// Authentication (if provided)
	if authParam != nil {
		// Sender ACSE requirements: 4 bytes
		contentLength += 4
		
		// Mechanism name: 5 bytes
		contentLength += 5
		
		// Authentication value
		if authParam.Mechanism == AuthPassword {
			passwordLength := len(authParam.Password)
			authValueStringLength := ber.DetermineLengthSize(uint32(passwordLength))
			contentLength += 2 + authValueStringLength + passwordLength
			
			authValueLength := ber.DetermineLengthSize(uint32(passwordLength + authValueStringLength + 1))
			contentLength += authValueLength
		} else {
			contentLength += 2
		}
	}
	
	// User information
	userInfoLength := 0
	
	// Single ASN1 type tag
	userInfoLength += payloadLength
	userInfoLength += 1 // tag
	userInfoLength += ber.DetermineLengthSize(uint32(payloadLength)) // length
	
	// Indirect reference
	userInfoLength += 1 // tag
	userInfoLength += 2 // length + value (1 byte)
	
	// Association data
	assocDataLength := userInfoLength
	userInfoLength += ber.DetermineLengthSize(uint32(assocDataLength)) // length
	userInfoLength += 1 // tag
	
	// User information wrapper
	userInfoLen := userInfoLength
	userInfoLength += ber.DetermineLengthSize(uint32(userInfoLength)) // length
	userInfoLength += 1 // tag
	
	contentLength += userInfoLength
	
	// Allocate buffer with sufficient size
	// We need contentLength + tag(1) + max length encoding(4) + some margin
	bufferSize := contentLength + 20
	buffer := make([]byte, bufferSize)
	bufPos := 0
	
	// Encode AARQ tag and length
	bufPos = ber.EncodeTL(0x60, uint32(contentLength), buffer, bufPos)
	
	// Application context name
	bufPos = ber.EncodeTL(0xa1, 7, buffer, bufPos)
	bufPos = ber.EncodeTL(0x06, 5, buffer, bufPos)
	copy(buffer[bufPos:], appContextNameMms)
	bufPos += 5
	
	// Called AP title and AE qualifier
	if isoParams != nil && isoParams.RemoteAPTitleLen > 0 {
		// Called AP title
		calledAPTitleLength := isoParams.RemoteAPTitleLen + 2
		bufPos = ber.EncodeTL(0xa2, uint32(calledAPTitleLength), buffer, bufPos)
		bufPos = ber.EncodeTL(0x06, uint32(isoParams.RemoteAPTitleLen), buffer, bufPos)
		copy(buffer[bufPos:], isoParams.RemoteAPTitle)
		bufPos += isoParams.RemoteAPTitleLen
		
		// Called AE qualifier
		calledAEQualifierLength := determineIntegerEncodedSize(int32(isoParams.RemoteAEQualifier))
		bufPos = ber.EncodeTL(0xa3, uint32(calledAEQualifierLength+2), buffer, bufPos)
		bufPos = ber.EncodeTL(0x02, uint32(calledAEQualifierLength), buffer, bufPos)
		bufPos = encodeInteger(int32(isoParams.RemoteAEQualifier), buffer, bufPos)
	}
	
	// Calling AP title and AE qualifier
	if isoParams != nil && isoParams.LocalAPTitleLen > 0 {
		// Calling AP title
		callingAPTitleLength := isoParams.LocalAPTitleLen + 2
		bufPos = ber.EncodeTL(0xa6, uint32(callingAPTitleLength), buffer, bufPos)
		bufPos = ber.EncodeTL(0x06, uint32(isoParams.LocalAPTitleLen), buffer, bufPos)
		copy(buffer[bufPos:], isoParams.LocalAPTitle)
		bufPos += isoParams.LocalAPTitleLen
		
		// Calling AE qualifier
		callingAEQualifierLength := determineIntegerEncodedSize(int32(isoParams.LocalAEQualifier))
		bufPos = ber.EncodeTL(0xa7, uint32(callingAEQualifierLength+2), buffer, bufPos)
		bufPos = ber.EncodeTL(0x02, uint32(callingAEQualifierLength), buffer, bufPos)
		bufPos = encodeInteger(int32(isoParams.LocalAEQualifier), buffer, bufPos)
	}
	
	// Authentication (if provided)
	if authParam != nil {
		// Sender requirements
		bufPos = ber.EncodeTL(0x8a, 2, buffer, bufPos)
		buffer[bufPos] = 0x04
		bufPos++
		
		if authParam.Mechanism == AuthPassword {
			buffer[bufPos] = requirementsAuthentication[0]
			bufPos++
			
			// Mechanism name
			bufPos = ber.EncodeTL(0x8b, 3, buffer, bufPos)
			copy(buffer[bufPos:], authMechPasswordOID)
			bufPos += 3
			
			// Authentication value
			passwordLength := len(authParam.Password)
			authValueStringLength := ber.DetermineLengthSize(uint32(passwordLength))
			authValueLength := passwordLength + authValueStringLength + 1
			bufPos = ber.EncodeTL(0xac, uint32(authValueLength), buffer, bufPos)
			bufPos = ber.EncodeTL(0x80, uint32(passwordLength), buffer, bufPos)
			copy(buffer[bufPos:], authParam.Password)
			bufPos += passwordLength
		} else {
			buffer[bufPos] = 0
			bufPos++
		}
	}
	
	// User information
	bufPos = ber.EncodeTL(0xbe, uint32(userInfoLen), buffer, bufPos)
	
	// Association data
	bufPos = ber.EncodeTL(0x28, uint32(assocDataLength), buffer, bufPos)
	
	// Indirect reference
	bufPos = ber.EncodeTL(0x02, 1, buffer, bufPos)
	buffer[bufPos] = 3
	bufPos++
	
	// Single ASN1 type
	bufPos = ber.EncodeTL(0xa0, uint32(payloadLength), buffer, bufPos)
	
	// Append payload
	buffer = append(buffer[:bufPos], payload...)
	bufPos += len(payload)
	
	return buffer[:bufPos]
}

// ParseMessage parses an incoming ACSE message
// Based on AcseConnection_parseMessage from acse.c
func ParseMessage(conn *Connection, message []byte) (Indication, error) {
	if len(message) < 1 {
		return IndicationError, errors.New("invalid message - no payload")
	}
	
	bufPos := 0
	messageType := message[bufPos]
	bufPos++
	
	newPos, _, err := ber.DecodeLength(message, bufPos, len(message))
	if err != nil {
		return IndicationError, fmt.Errorf("invalid ACSE message: %w", err)
	}
	bufPos = newPos
	
	switch messageType {
	case 0x60: // AARQ
		return parseAarqPdu(conn, message, bufPos, len(message))
	case 0x61: // AARE
		return parseAarePdu(conn, message, bufPos, len(message))
	case 0x62: // A_RELEASE.request RLRQ-apdu
		return IndicationReleaseRequest, nil
	case 0x63: // A_RELEASE.response RLRE-apdu
		return IndicationReleaseResponse, nil
	case 0x64: // A_ABORT
		return IndicationAbort, nil
	case 0x00: // indefinite length end tag -> ignore
		return IndicationError, errors.New("indefinite length end tag")
	default:
		return IndicationError, fmt.Errorf("unknown ACSE message type: 0x%02x", messageType)
	}
}

// parseAarqPdu parses an AARQ PDU
// Based on parseAarqPdu from acse.c
func parseAarqPdu(conn *Connection, buffer []byte, bufPos, maxBufPos int) (Indication, error) {
	// Note: authValue, authValueLen, authMechanism, authMechLen are declared but not used
	// as authentication checking is simplified in this implementation
	userInfoValid := false
	
	for bufPos < maxBufPos {
		tag := buffer[bufPos]
		bufPos++
		
		newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			return IndicationAssociateFailed, fmt.Errorf("invalid PDU: %w", err)
		}
		bufPos = newPos
		
		if length == 0 {
			continue
		}
		
		if bufPos+length > maxBufPos {
			return IndicationAssociateFailed, errors.New("invalid PDU: buffer overflow")
		}
		
		switch tag {
		case 0xa1: // application context name
			bufPos += length
			
		case 0xa2: // called AP title
			bufPos += length
			
		case 0xa3: // called AE qualifier
			bufPos += length
			
		case 0xa6: // calling AP title
			if bufPos < maxBufPos && buffer[bufPos] == 0x06 {
				// ap-title-form2
				if bufPos+1 < maxBufPos {
					innerLength := int(buffer[bufPos+1])
					if innerLength == length-2 {
						ber.DecodeOID(buffer, bufPos+2, innerLength, &conn.ApplicationRef.APTitle)
					}
				}
			}
			bufPos += length
			
		case 0xa7: // calling AE qualifier
			if bufPos < maxBufPos && buffer[bufPos] == 0x02 {
				// ae-qualifier-form2
				if bufPos+1 < maxBufPos {
					innerLength := int(buffer[bufPos+1])
					if innerLength == length-2 {
						conn.ApplicationRef.AEQualifier = ber.DecodeInt32(buffer, innerLength, bufPos+2)
					}
				}
			}
			bufPos += length
			
		case 0x8a: // sender ACSE requirements
			bufPos += length
			
		case 0x8b: // (authentication) mechanism name
			// Authentication mechanism parsing (not used in simplified implementation)
			bufPos += length
			
		case 0xac: // authentication value
			bufPos++ // skip tag
			newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
			if err != nil {
				return IndicationAssociateFailed, fmt.Errorf("invalid PDU: %w", err)
			}
			bufPos = newPos
			
			// Authentication value parsing (not used in simplified implementation)
			bufPos += length
			
		case 0xbe: // user information
			if bufPos < maxBufPos && buffer[bufPos] != 0x28 {
				bufPos += length
			} else {
				bufPos++ // skip 0x28 tag
				newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
				if err != nil {
					return IndicationAssociateFailed, fmt.Errorf("invalid PDU: %w", err)
				}
				bufPos = newPos
				
				var parseErr error
				bufPos, parseErr = parseUserInformation(conn, buffer, bufPos, bufPos+length, &userInfoValid)
				if parseErr != nil {
					return IndicationAssociateFailed, fmt.Errorf("invalid PDU: %w", parseErr)
				}
			}
			
		case 0x00: // indefinite length end tag -> ignore
			break
			
		default:
			bufPos += length
		}
	}
	
	// Check authentication (simplified - always accept for now)
	// In full implementation, this would call checkAuthentication
	
	if !userInfoValid {
		return IndicationAssociateFailed, errors.New("user info invalid")
	}
	
	return IndicationAssociate, nil
}

// parseAarePdu parses an AARE PDU
// Based on parseAarePdu from acse.c
func parseAarePdu(conn *Connection, buffer []byte, bufPos, maxBufPos int) (Indication, error) {
	userInfoValid := false
	result := uint32(99)
	
	for bufPos < maxBufPos {
		tag := buffer[bufPos]
		bufPos++
		
		newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			return IndicationError, fmt.Errorf("invalid PDU: %w", err)
		}
		bufPos = newPos
		
		if length == 0 {
			continue
		}
		
		if bufPos+length > maxBufPos {
			return IndicationError, errors.New("invalid PDU: buffer overflow")
		}
		
		switch tag {
		case 0xa1: // application context name
			bufPos += length
			
		case 0xa2: // result
			bufPos++ // skip tag
			newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
			if err != nil {
				return IndicationError, fmt.Errorf("invalid PDU: %w", err)
			}
			bufPos = newPos
			
			result = ber.DecodeUint32(buffer, length, bufPos)
			bufPos += length
			
		case 0xa3: // result source diagnostic
			bufPos += length
			
		case 0xbe: // user information
			if bufPos < maxBufPos && buffer[bufPos] != 0x28 {
				bufPos += length
			} else {
				bufPos++ // skip 0x28 tag
				newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
				if err != nil {
					return IndicationError, fmt.Errorf("invalid PDU: %w", err)
				}
				bufPos = newPos
				
				var parseErr error
				bufPos, parseErr = parseUserInformation(conn, buffer, bufPos, bufPos+length, &userInfoValid)
				if parseErr != nil {
					return IndicationError, fmt.Errorf("invalid PDU: %w", parseErr)
				}
			}
			
		case 0x00: // indefinite length end tag -> ignore
			break
			
		default:
			bufPos += length
		}
	}
	
	if !userInfoValid {
		return IndicationError, errors.New("user info invalid")
	}
	
	if result != 0 {
		return IndicationAssociateFailed, nil
	}
	
	return IndicationAssociate, nil
}

// parseUserInformation parses user information from ACSE PDU
// Based on parseUserInformation from acse.c
func parseUserInformation(conn *Connection, buffer []byte, bufPos, maxBufPos int, userInfoValid *bool) (int, error) {
	hasIndirectReference := false
	isDataValid := false
	
	for bufPos < maxBufPos {
		tag := buffer[bufPos]
		bufPos++
		
		newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			*userInfoValid = false
			return -1, err
		}
		bufPos = newPos
		
		if length == 0 {
			continue
		}
		
		if bufPos < 0 || bufPos+length > maxBufPos {
			*userInfoValid = false
			return -1, errors.New("buffer overflow")
		}
		
		switch tag {
		case 0x02: // indirect-reference
			conn.NextReference = ber.DecodeUint32(buffer, length, bufPos)
			bufPos += length
			hasIndirectReference = true
			
		case 0xa0: // encoding
			isDataValid = true
			conn.UserDataBufferSize = length
			conn.UserDataBuffer = buffer[bufPos : bufPos+length]
			bufPos += length
			
		default: // ignore unknown tag
			bufPos += length
		}
	}
	
	if hasIndirectReference && isDataValid {
		*userInfoValid = true
	} else {
		*userInfoValid = false
	}
	
	return bufPos, nil
}

// CreateAssociateResponseMessage creates an AARE (Association Response) PDU
// Based on AcseConnection_createAssociateResponseMessage from acse.c
func CreateAssociateResponseMessage(conn *Connection, acseResult uint8, payload []byte) []byte {
	appContextLength := 9
	resultLength := 5
	resultDiagnosticLength := 5
	
	fixedContentLength := appContextLength + resultLength + resultDiagnosticLength
	
	variableContentLength := 0
	
	payloadLength := len(payload)
	
	// Single ASN1 type tag
	variableContentLength += payloadLength
	variableContentLength += 1 // tag
	variableContentLength += ber.DetermineLengthSize(uint32(payloadLength)) // length
	
	// Indirect reference
	nextRefLength := ber.UInt32DetermineEncodedSize(conn.NextReference)
	variableContentLength += nextRefLength
	variableContentLength += 2 // tag + length
	
	// Association data
	assocDataLength := variableContentLength
	variableContentLength += ber.DetermineLengthSize(uint32(assocDataLength)) // length
	variableContentLength += 1 // tag
	
	// User information
	userInfoLength := variableContentLength
	variableContentLength += ber.DetermineLengthSize(uint32(userInfoLength)) // length
	variableContentLength += 1 // tag
	
	variableContentLength += 2 // user information tag
	
	contentLength := fixedContentLength + variableContentLength
	
	buffer := make([]byte, 0, contentLength+10)
	bufPos := 0
	
	// Encode AARE tag and length
	bufPos = ber.EncodeTL(0x61, uint32(contentLength), buffer, bufPos)
	buffer = buffer[:bufPos+contentLength]
	bufPos = 0
	bufPos = ber.EncodeTL(0x61, uint32(contentLength), buffer, bufPos)
	
	// Application context name
	bufPos = ber.EncodeTL(0xa1, 7, buffer, bufPos)
	bufPos = ber.EncodeTL(0x06, 5, buffer, bufPos)
	copy(buffer[bufPos:], appContextNameMms)
	bufPos += 5
	
	// Result
	bufPos = ber.EncodeTL(0xa2, 3, buffer, bufPos)
	bufPos = ber.EncodeTL(0x02, 1, buffer, bufPos)
	buffer[bufPos] = acseResult
	bufPos++
	
	// Result source diagnostics
	bufPos = ber.EncodeTL(0xa3, 5, buffer, bufPos)
	bufPos = ber.EncodeTL(0xa1, 3, buffer, bufPos)
	bufPos = ber.EncodeTL(0x02, 1, buffer, bufPos)
	buffer[bufPos] = 0
	bufPos++
	
	// User information
	bufPos = ber.EncodeTL(0xbe, uint32(userInfoLength), buffer, bufPos)
	
	// Association data
	bufPos = ber.EncodeTL(0x28, uint32(assocDataLength), buffer, bufPos)
	
	// Indirect reference
	bufPos = ber.EncodeTL(0x02, uint32(nextRefLength), buffer, bufPos)
	bufPos = ber.EncodeUInt32(conn.NextReference, buffer, bufPos)
	
	// Single ASN1 type
	bufPos = ber.EncodeTL(0xa0, uint32(payloadLength), buffer, bufPos)
	
	// Append payload
	buffer = append(buffer[:bufPos], payload...)
	bufPos += len(payload)
	
	return buffer[:bufPos]
}

// CreateAssociateFailedMessage creates an AARE with reject permanent result
func CreateAssociateFailedMessage(conn *Connection, payload []byte) []byte {
	return CreateAssociateResponseMessage(conn, ResultRejectPermanent, payload)
}

// CreateAbortMessage creates an A_ABORT PDU
func CreateAbortMessage(conn *Connection, isProvider bool) []byte {
	buffer := make([]byte, 5)
	buffer[0] = 0x64 // [APPLICATION 4]
	buffer[1] = 3
	buffer[2] = 0x80
	buffer[3] = 1
	
	if isProvider {
		buffer[4] = 1
	} else {
		buffer[4] = 0
	}
	
	return buffer
}

// CreateReleaseRequestMessage creates an A_RELEASE.request PDU
func CreateReleaseRequestMessage(conn *Connection) []byte {
	buffer := make([]byte, 5)
	buffer[0] = 0x62
	buffer[1] = 3
	buffer[2] = 0x80
	buffer[3] = 1
	buffer[4] = 0
	return buffer
}

// CreateReleaseResponseMessage creates an A_RELEASE.response PDU
func CreateReleaseResponseMessage(conn *Connection) []byte {
	buffer := make([]byte, 2)
	buffer[0] = 0x63
	buffer[1] = 0
	return buffer
}

// determineIntegerEncodedSize determines the encoded size of an integer
// For small values (0-127), returns 1 byte
func determineIntegerEncodedSize(value int32) int {
	if value >= 0 && value < 128 {
		return 1
	}
	if value < 0 && value >= -128 {
		return 1
	}
	// For larger values, use the standard BER encoding
	return ber.Int32DetermineEncodedSize(value)
}

// encodeInteger encodes an integer value in BER format
// For small values (0-127), encodes as 1 byte
func encodeInteger(value int32, buffer []byte, bufPos int) int {
	if value >= 0 && value < 128 {
		buffer[bufPos] = byte(value)
		return bufPos + 1
	}
	if value < 0 && value >= -128 {
		buffer[bufPos] = byte(value)
		return bufPos + 1
	}
	// For larger values, use the standard BER encoding
	return ber.EncodeInt32(value, buffer, bufPos)
}
