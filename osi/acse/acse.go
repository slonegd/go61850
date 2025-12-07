package acse

import (
	"errors"
	"fmt"
	"strings"

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
	ResultAccept          = 0
	ResultRejectPermanent = 1
	ResultRejectTransient = 2
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
	Mechanism   AuthenticationMechanism
	Password    []byte // for ACSE_AUTH_PASSWORD
	Certificate []byte // for ACSE_AUTH_CERTIFICATE or ACSE_AUTH_TLS
}

// ApplicationReference represents ISO application reference
type ApplicationReference struct {
	APTitle     ber.ItuObjectIdentifier
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
	// 1.0.9506.2.3 (mms-abstract-syntax-version3)
	appContextNameMms = []byte{0x28, 0xca, 0x22, 0x02, 0x03}
	// 2.2.3.1 (id-password)
	authMechPasswordOID = []byte{0x52, 0x03, 0x01}
	// Authentication requirements
	requirementsAuthentication = []byte{0x80}
)

// BuildAARQ creates an AARQ (Association Request) PDU
// This is a simplified version that matches the expected packet structure
func BuildAARQ(userData []byte) []byte {
	conn := NewConnection()
	isoParams := &IsoConnectionParameters{
		RemoteAPTitle:     []byte{0x29, 0x01, 0x87, 0x67, 0x01},
		RemoteAPTitleLen:  5,
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
	userInfoLength += 1                                              // tag
	userInfoLength += ber.DetermineLengthSize(uint32(payloadLength)) // length

	// Indirect reference
	userInfoLength += 1 // tag
	userInfoLength += 2 // length + value (1 byte)

	// Association data
	assocDataLength := userInfoLength
	userInfoLength += ber.DetermineLengthSize(uint32(assocDataLength)) // length
	userInfoLength += 1                                                // tag

	// User information wrapper
	userInfoLen := userInfoLength
	userInfoLength += ber.DetermineLengthSize(uint32(userInfoLength)) // length
	userInfoLength += 1                                               // tag

	contentLength += userInfoLength

	// Allocate buffer with sufficient size
	// We need contentLength + tag(1) + max length encoding(4) + some margin
	bufferSize := contentLength + 20
	buffer := make([]byte, bufferSize)
	bufPos := 0

	// Encode AARQ tag and length
	bufPos = ber.EncodeTL(ber.Application0Constructed, uint32(contentLength), buffer, bufPos)

	// Application context name
	bufPos = ber.EncodeTL(ber.ContextSpecific1Constructed, 7, buffer, bufPos)
	bufPos = ber.EncodeTL(ber.ObjectIdentifier, 5, buffer, bufPos)
	copy(buffer[bufPos:], appContextNameMms)
	bufPos += 5

	// Called AP title and AE qualifier
	if isoParams != nil && isoParams.RemoteAPTitleLen > 0 {
		// Called AP title
		calledAPTitleLength := isoParams.RemoteAPTitleLen + 2
		bufPos = ber.EncodeTL(ber.ContextSpecific2Constructed, uint32(calledAPTitleLength), buffer, bufPos)
		bufPos = ber.EncodeTL(ber.ObjectIdentifier, uint32(isoParams.RemoteAPTitleLen), buffer, bufPos)
		copy(buffer[bufPos:], isoParams.RemoteAPTitle)
		bufPos += isoParams.RemoteAPTitleLen

		// Called AE qualifier
		calledAEQualifierLength := determineIntegerEncodedSize(int32(isoParams.RemoteAEQualifier))
		bufPos = ber.EncodeTL(ber.ContextSpecific3Constructed, uint32(calledAEQualifierLength+2), buffer, bufPos)
		bufPos = ber.EncodeTL(ber.Integer, uint32(calledAEQualifierLength), buffer, bufPos)
		bufPos = encodeInteger(int32(isoParams.RemoteAEQualifier), buffer, bufPos)
	}

	// Calling AP title and AE qualifier
	if isoParams != nil && isoParams.LocalAPTitleLen > 0 {
		// Calling AP title
		callingAPTitleLength := isoParams.LocalAPTitleLen + 2
		bufPos = ber.EncodeTL(ber.ContextSpecific6Constructed, uint32(callingAPTitleLength), buffer, bufPos)
		bufPos = ber.EncodeTL(ber.ObjectIdentifier, uint32(isoParams.LocalAPTitleLen), buffer, bufPos)
		copy(buffer[bufPos:], isoParams.LocalAPTitle)
		bufPos += isoParams.LocalAPTitleLen

		// Calling AE qualifier
		callingAEQualifierLength := determineIntegerEncodedSize(int32(isoParams.LocalAEQualifier))
		bufPos = ber.EncodeTL(ber.ContextSpecific7Constructed, uint32(callingAEQualifierLength+2), buffer, bufPos)
		bufPos = ber.EncodeTL(ber.Integer, uint32(callingAEQualifierLength), buffer, bufPos)
		bufPos = encodeInteger(int32(isoParams.LocalAEQualifier), buffer, bufPos)
	}

	// Authentication (if provided)
	if authParam != nil {
		// Sender requirements
		bufPos = ber.EncodeTL(ber.ContextSpecific10Primitive, 2, buffer, bufPos)
		buffer[bufPos] = 0x04
		bufPos++

		if authParam.Mechanism == AuthPassword {
			buffer[bufPos] = requirementsAuthentication[0]
			bufPos++

			// Mechanism name
			bufPos = ber.EncodeTL(ber.ContextSpecific11Primitive, 3, buffer, bufPos)
			copy(buffer[bufPos:], authMechPasswordOID)
			bufPos += 3

			// Authentication value
			passwordLength := len(authParam.Password)
			authValueStringLength := ber.DetermineLengthSize(uint32(passwordLength))
			authValueLength := passwordLength + authValueStringLength + 1
			bufPos = ber.EncodeTL(ber.ContextSpecific12Constructed, uint32(authValueLength), buffer, bufPos)
			bufPos = ber.EncodeTL(ber.ContextSpecific0Primitive, uint32(passwordLength), buffer, bufPos)
			copy(buffer[bufPos:], authParam.Password)
			bufPos += passwordLength
		} else {
			buffer[bufPos] = 0
			bufPos++
		}
	}

	// User information
	bufPos = ber.EncodeTL(ber.ContextSpecific30Constructed, uint32(userInfoLen), buffer, bufPos)

	// Association data
	bufPos = ber.EncodeTL(ber.ExternalConstructed, uint32(assocDataLength), buffer, bufPos)

	// Indirect reference
	bufPos = ber.EncodeTL(ber.Integer, 1, buffer, bufPos)
	buffer[bufPos] = 3
	bufPos++

	// Single ASN1 type
	bufPos = ber.EncodeTL(ber.ContextSpecific0Constructed, uint32(payloadLength), buffer, bufPos)

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
	variableContentLength += 1                                              // tag
	variableContentLength += ber.DetermineLengthSize(uint32(payloadLength)) // length

	// Indirect reference
	nextRefLength := ber.UInt32DetermineEncodedSize(conn.NextReference)
	variableContentLength += nextRefLength
	variableContentLength += 2 // tag + length

	// Association data
	assocDataLength := variableContentLength
	variableContentLength += ber.DetermineLengthSize(uint32(assocDataLength)) // length
	variableContentLength += 1                                                // tag

	// User information
	userInfoLength := variableContentLength
	variableContentLength += ber.DetermineLengthSize(uint32(userInfoLength)) // length
	variableContentLength += 1                                               // tag

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

// ACSEPDUType represents the type of ACSE PDU
type ACSEPDUType uint8

const (
	AARQ ACSEPDUType = 0x60 // AARQ (Association Request)
	AARE ACSEPDUType = 0x61 // AARE (Association Response)
	RLRQ ACSEPDUType = 0x62 // RLRQ (Release Request)
	RLRE ACSEPDUType = 0x63 // RLRE (Release Response)
	ABRT ACSEPDUType = 0x64 // ABRT (Abort)
)

// ACSEPDU represents an ACSE Protocol Data Unit for logging purposes
// Based on parseAarePdu and parseAarqPdu from acse.c
type ACSEPDU struct {
	Type                   ACSEPDUType
	ApplicationContextName []byte // OID (e.g., 1.0.9506.2.3 for MMS)
	Result                 uint32 // Result code (for AARE: 0=accepted, 1=reject-permanent, 2=reject-transient)
	ResultSourceDiagnostic uint32 // Result source diagnostic (for AARE: 1=service-user)
	IndirectReference      uint32 // Indirect reference from user information
	Encoding               uint8  // Encoding type (0=single-ASN1-type)
	Data                   []byte // MMS data (user data)
}

// ParseACSEPDU parses an ACSE PDU from byte buffer and returns a structure for logging
// Based on AcseConnection_parseMessage, parseAarqPdu, and parseAarePdu from acse.c
func ParseACSEPDU(data []byte) (*ACSEPDU, error) {
	if len(data) < 1 {
		return nil, errors.New("ACSE PDU too short: need at least 1 byte")
	}

	pdu := &ACSEPDU{}
	bufPos := 0
	messageType := data[bufPos]
	bufPos++

	newPos, _, err := ber.DecodeLength(data, bufPos, len(data))
	if err != nil {
		return nil, fmt.Errorf("invalid ACSE message: %w", err)
	}
	bufPos = newPos

	maxBufPos := len(data)

	pduType := ACSEPDUType(messageType)
	switch pduType {
	case AARQ:
		pdu.Type = AARQ
		return parseAarqPduForLogging(pdu, data, bufPos, maxBufPos)
	case AARE:
		pdu.Type = AARE
		return parseAarePduForLogging(pdu, data, bufPos, maxBufPos)
	case RLRQ:
		pdu.Type = RLRQ
		return pdu, nil
	case RLRE:
		pdu.Type = RLRE
		return pdu, nil
	case ABRT:
		pdu.Type = ABRT
		return pdu, nil
	default:
		return nil, fmt.Errorf("unknown ACSE message type: 0x%02x", messageType)
	}
}

// parseAarePduForLogging parses an AARE PDU for logging purposes
// Based on parseAarePdu from acse.c (lines 183-279)
func parseAarePduForLogging(pdu *ACSEPDU, buffer []byte, bufPos, maxBufPos int) (*ACSEPDU, error) {
	userInfoValid := false
	result := uint32(99)

	for bufPos < maxBufPos {
		tag := buffer[bufPos]
		bufPos++

		newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			return nil, fmt.Errorf("invalid PDU: %w", err)
		}
		bufPos = newPos

		if length == 0 {
			continue
		}

		if bufPos+length > maxBufPos {
			return nil, errors.New("invalid PDU: buffer overflow")
		}

		switch tag {
		case 0xa1: // application context name
			if length > 0 && bufPos+length <= maxBufPos {
				// Skip OID tag (0x06) and get OID value
				if bufPos < maxBufPos && buffer[bufPos] == 0x06 {
					bufPos++ // skip OID tag
					if bufPos < maxBufPos {
						oidLength := int(buffer[bufPos])
						bufPos++
						if oidLength > 0 && bufPos+oidLength <= maxBufPos {
							pdu.ApplicationContextName = make([]byte, oidLength)
							copy(pdu.ApplicationContextName, buffer[bufPos:bufPos+oidLength])
							bufPos += oidLength
						} else {
							bufPos += length - 2
						}
					} else {
						bufPos += length - 1
					}
				} else {
					bufPos += length
				}
			} else {
				bufPos += length
			}

		case 0xa2: // result
			bufPos++ // skip tag
			newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
			if err != nil {
				return nil, fmt.Errorf("invalid PDU: %w", err)
			}
			bufPos = newPos

			result = ber.DecodeUint32(buffer, length, bufPos)
			pdu.Result = result
			bufPos += length

		case 0xa3: // result source diagnostic
			// Parse result source diagnostic
			// According to ISO 8650-1, result-source-diagnostic can be:
			// - service-user (0xa1): value = 1
			// - service-provider (0xa2): value = 2
			if bufPos < maxBufPos {
				diagTag := buffer[bufPos]
				bufPos++
				if bufPos < maxBufPos {
					newPos, diagLength, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
					if err == nil {
						bufPos = newPos
						if diagTag == 0xa1 { // service-user
							// service-user means ResultSourceDiagnostic = 1
							pdu.ResultSourceDiagnostic = 1
							// Skip the rest of the diagnostic (the null value inside)
							bufPos += diagLength
						} else if diagTag == 0xa2 { // service-provider
							// service-provider means ResultSourceDiagnostic = 2
							pdu.ResultSourceDiagnostic = 2
							bufPos += diagLength
						} else {
							bufPos += diagLength
						}
					} else {
						bufPos += length - 1
					}
				} else {
					bufPos += length - 1
				}
			} else {
				bufPos += length
			}

		case 0xbe: // user information
			if bufPos < maxBufPos && buffer[bufPos] != 0x28 {
				bufPos += length
			} else {
				bufPos++ // skip 0x28 tag
				newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
				if err != nil {
					return nil, fmt.Errorf("invalid PDU: %w", err)
				}
				bufPos = newPos

				// Parse user information
				userInfoEnd := bufPos + length
				for bufPos < userInfoEnd && bufPos < maxBufPos {
					userTag := buffer[bufPos]
					bufPos++

					if bufPos >= maxBufPos {
						break
					}

					newPos, userLength, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
					if err != nil {
						break
					}
					bufPos = newPos

					switch userTag {
					case 0x02: // indirect-reference
						pdu.IndirectReference = ber.DecodeUint32(buffer, userLength, bufPos)
						bufPos += userLength
						userInfoValid = true

					case 0xa0: // encoding (single-ASN1-type)
						pdu.Encoding = 0 // single-ASN1-type
						if bufPos+userLength <= maxBufPos {
							pdu.Data = make([]byte, userLength)
							copy(pdu.Data, buffer[bufPos:bufPos+userLength])
							bufPos += userLength
							userInfoValid = true
						} else {
							bufPos += userLength
						}

					default:
						bufPos += userLength
					}
				}
			}

		case 0x00: // indefinite length end tag -> ignore
			break

		default:
			bufPos += length
		}
	}

	if !userInfoValid {
		return nil, errors.New("user info invalid")
	}

	return pdu, nil
}

// parseAarqPduForLogging parses an AARQ PDU for logging purposes
// Based on parseAarqPdu from acse.c (lines 281-446)
func parseAarqPduForLogging(pdu *ACSEPDU, buffer []byte, bufPos, maxBufPos int) (*ACSEPDU, error) {
	userInfoValid := false

	for bufPos < maxBufPos {
		tag := buffer[bufPos]
		bufPos++

		newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			return nil, fmt.Errorf("invalid PDU: %w", err)
		}
		bufPos = newPos

		if length == 0 {
			continue
		}

		if bufPos+length > maxBufPos {
			return nil, errors.New("invalid PDU: buffer overflow")
		}

		switch tag {
		case 0xa1: // application context name
			if length > 0 && bufPos+length <= maxBufPos {
				// Skip OID tag (0x06) and get OID value
				if bufPos < maxBufPos && buffer[bufPos] == 0x06 {
					bufPos++ // skip OID tag
					if bufPos < maxBufPos {
						oidLength := int(buffer[bufPos])
						bufPos++
						if oidLength > 0 && bufPos+oidLength <= maxBufPos {
							pdu.ApplicationContextName = make([]byte, oidLength)
							copy(pdu.ApplicationContextName, buffer[bufPos:bufPos+oidLength])
							bufPos += oidLength
						} else {
							bufPos += length - 2
						}
					} else {
						bufPos += length - 1
					}
				} else {
					bufPos += length
				}
			} else {
				bufPos += length
			}

		case 0xa2, 0xa3, 0xa6, 0xa7, 0x8a, 0x8b, 0xac: // other fields we skip
			bufPos += length

		case 0xbe: // user information
			if bufPos < maxBufPos && buffer[bufPos] != 0x28 {
				bufPos += length
			} else {
				bufPos++ // skip 0x28 tag
				newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
				if err != nil {
					return nil, fmt.Errorf("invalid PDU: %w", err)
				}
				bufPos = newPos

				// Parse user information
				userInfoEnd := bufPos + length
				for bufPos < userInfoEnd && bufPos < maxBufPos {
					userTag := buffer[bufPos]
					bufPos++

					if bufPos >= maxBufPos {
						break
					}

					newPos, userLength, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
					if err != nil {
						break
					}
					bufPos = newPos

					switch userTag {
					case 0x02: // indirect-reference
						pdu.IndirectReference = ber.DecodeUint32(buffer, userLength, bufPos)
						bufPos += userLength
						userInfoValid = true

					case 0xa0: // encoding (single-ASN1-type)
						pdu.Encoding = 0 // single-ASN1-type
						if bufPos+userLength <= maxBufPos {
							pdu.Data = make([]byte, userLength)
							copy(pdu.Data, buffer[bufPos:bufPos+userLength])
							bufPos += userLength
							userInfoValid = true
						} else {
							bufPos += userLength
						}

					default:
						bufPos += userLength
					}
				}
			}

		case 0x00: // indefinite length end tag -> ignore
			break

		default:
			bufPos += length
		}
	}

	if !userInfoValid {
		return nil, errors.New("user info invalid")
	}

	return pdu, nil
}

// String implements fmt.Stringer for ACSEPDU
func (p *ACSEPDU) String() string {
	var builder strings.Builder

	typeStr := ""
	switch p.Type {
	case AARQ:
		typeStr = "AARQ"
	case AARE:
		typeStr = "AARE"
	case RLRQ:
		typeStr = "RLRQ"
	case RLRE:
		typeStr = "RLRE"
	case ABRT:
		typeStr = "ABRT"
	default:
		typeStr = fmt.Sprintf("Unknown(0x%02x)", uint8(p.Type))
	}

	builder.WriteString("ACSEPDU{Type: ")
	builder.WriteString(typeStr)
	fmt.Fprintf(&builder, " (0x%02x)", uint8(p.Type))

	if len(p.ApplicationContextName) > 0 {
		// Format OID
		oidStr := formatOID(p.ApplicationContextName)
		builder.WriteString(", ApplicationContextName: ")
		builder.WriteString(oidStr)
	}

	if p.Type == AARE {
		resultStr := ""
		switch p.Result {
		case 0:
			resultStr = "accepted"
		case 1:
			resultStr = "reject-permanent"
		case 2:
			resultStr = "reject-transient"
		default:
			resultStr = fmt.Sprintf("unknown(%d)", p.Result)
		}
		fmt.Fprintf(&builder, ", Result: %d (%s)", p.Result, resultStr)

		if p.ResultSourceDiagnostic != 0 {
			diagStr := ""
			if p.ResultSourceDiagnostic == 1 {
				diagStr = "service-user (1)"
			} else {
				diagStr = fmt.Sprintf("%d", p.ResultSourceDiagnostic)
			}
			fmt.Fprintf(&builder, ", ResultSourceDiagnostic: %s", diagStr)
		}
	}

	if p.IndirectReference != 0 {
		fmt.Fprintf(&builder, ", IndirectReference: %d", p.IndirectReference)
	}

	if p.Encoding == 0 {
		fmt.Fprintf(&builder, ", Encoding: %d (single-ASN1-type)", p.Encoding)
	} else if p.Encoding != 0 {
		fmt.Fprintf(&builder, ", Encoding: %d", p.Encoding)
	}

	fmt.Fprintf(&builder, ", DataLength: %d}", len(p.Data))

	return builder.String()
}

// formatOID formats an OID byte array as a string
func formatOID(oid []byte) string {
	if len(oid) == 0 {
		return "[]"
	}
	if len(oid) == 5 && oid[0] == 0x28 && oid[1] == 0xca && oid[2] == 0x22 && oid[3] == 0x02 && oid[4] == 0x03 {
		return "1.0.9506.2.3 (MMS)"
	}
	if len(oid) == 4 && oid[0] == 0x52 && oid[1] == 0x01 && oid[2] == 0x00 && oid[3] == 0x01 {
		return "2.2.1.0.1 (id-as-acse)"
	}
	// Generic OID formatting
	var parts []string
	for _, b := range oid {
		parts = append(parts, fmt.Sprintf("%02x", b))
	}
	return fmt.Sprintf("[%s]", strings.Join(parts, " "))
}
