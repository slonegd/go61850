package presentation

import (
	"github.com/slonegd/go61850/ber"
)

// PSelector представляет селектор представления
type PSelector struct {
	Value []byte
}

// Presentation представляет состояние представления ISO 8823
type Presentation struct {
	callingPresentationSelector PSelector
	calledPresentationSelector  PSelector
	acseContextId               uint8
	mmsContextId                uint8
	nextContextId               uint8
}

// NewPresentation создаёт новое представление с параметрами по умолчанию
// Согласно IsoPresentation_init из C библиотеки и createConnectPdu:
// - acseContextId = 1
// - mmsContextId = 3
// - callingPresentationSelector = [0, 0, 0, 1]
// - calledPresentationSelector = [0, 0, 0, 1]
func NewPresentation() *Presentation {
	return &Presentation{
		acseContextId: 1,
		mmsContextId:  3,
		callingPresentationSelector: PSelector{
			Value: []byte{0, 0, 0, 1},
		},
		calledPresentationSelector: PSelector{
			Value: []byte{0, 0, 0, 1},
		},
	}
}

// Константы для OID
var (
	asnIDAsACSE = []byte{0x52, 0x01, 0x00, 0x01}       // 2.2.1.0.1 (id-as-acse)
	asnIDMMS    = []byte{0x28, 0xca, 0x22, 0x02, 0x01} // 1.0.9506.2.1 (mms-abstract-syntax-version1)
	berID       = []byte{0x51, 0x01}                   // 2.1.1 (basic-encoding)
)

// encodeUserData кодирует user data согласно encodeUserData из C библиотеки (строки 59-97)
func encodeUserData(presentation *Presentation, userData []byte, buf []byte, bufPos int, encode bool) int {
	payloadLength := len(userData)

	encodedDataSetLength := 3 // presentation-selector

	// presentation-data
	encodedDataSetLength += payloadLength + 1
	encodedDataSetLength += ber.DetermineLengthSize(uint32(payloadLength))

	fullyEncodedDataLength := encodedDataSetLength
	fullyEncodedDataLength += ber.DetermineLengthSize(uint32(encodedDataSetLength)) + 1

	if encode {
		// fully-encoded-data (Application 1, Constructed) = 0x61
		bufPos = ber.EncodeTL(ber.Application1Constructed, uint32(fullyEncodedDataLength), buf, bufPos)
		// SEQUENCE (Constructed) = 0x30
		bufPos = ber.EncodeTL(ber.SequenceConstructed, uint32(encodedDataSetLength), buf, bufPos)

		// presentation-selector acse (INTEGER) = 0x02
		bufPos = ber.EncodeTL(ber.Integer, 1, buf, bufPos)
		buf[bufPos] = presentation.acseContextId
		bufPos++

		// presentation-data (= acse payload) (Context-specific 0, Constructed) = 0xa0
		bufPos = ber.EncodeTL(ber.ContextSpecific0Constructed, uint32(payloadLength), buf, bufPos)

		return bufPos
	} else {
		encodedUserDataLength := fullyEncodedDataLength + 1
		encodedUserDataLength += ber.DetermineLengthSize(uint32(fullyEncodedDataLength))
		return encodedUserDataLength
	}
}

// createConnectPdu создаёт CP-type PDU согласно createConnectPdu из C библиотеки (строки 99-189)
func createConnectPdu(presentation *Presentation, userData []byte) []byte {
	contentLength := 0
	// mode-selector
	contentLength += 5

	normalModeLength := 0

	// called- and calling-presentation-selector
	normalModeLength += 12

	// presentation-context-definition-list
	pclLength := 27
	pclLength += len(presentation.callingPresentationSelector.Value)
	pclLength += len(presentation.calledPresentationSelector.Value)

	normalModeLength += pclLength

	normalModeLength += encodeUserData(presentation, userData, nil, 0, false)

	normalModeLength += 2

	contentLength += normalModeLength
	contentLength += 1 + ber.DetermineLengthSize(uint32(normalModeLength))

	// Создаём буфер достаточного размера
	buf := make([]byte, contentLength+len(userData)+100)
	bufPos := 0

	// CP-type (SET, Constructed) = 0x31
	bufPos = ber.EncodeTL(ber.SetConstructed, uint32(contentLength), buf, bufPos)

	// mode-selector (Context-specific 0, Constructed) = 0xa0
	bufPos = ber.EncodeTL(ber.ContextSpecific0Constructed, 3, buf, bufPos)
	// mode-value: normal-mode (1) (Context-specific 0, INTEGER) = 0x80
	bufPos = ber.EncodeTL(ber.ContextSpecific0Primitive, 1, buf, bufPos)
	buf[bufPos] = 1 // 1 = normal-mode
	bufPos++

	// normal-mode-parameters (Context-specific 2, Constructed) = 0xa2
	bufPos = ber.EncodeTL(ber.ContextSpecific2Constructed, uint32(normalModeLength), buf, bufPos)

	// calling-presentation-selector (Context-specific 1, OCTET STRING) = 0x81
	bufPos = ber.EncodeTL(ber.ContextSpecific1Primitive, uint32(len(presentation.callingPresentationSelector.Value)), buf, bufPos)
	for i := 0; i < len(presentation.callingPresentationSelector.Value); i++ {
		buf[bufPos] = presentation.callingPresentationSelector.Value[i]
		bufPos++
	}

	// called-presentation-selector (Context-specific 2, OCTET STRING) = 0x82
	bufPos = ber.EncodeTL(ber.ContextSpecific2Primitive, uint32(len(presentation.calledPresentationSelector.Value)), buf, bufPos)
	for i := 0; i < len(presentation.calledPresentationSelector.Value); i++ {
		buf[bufPos] = presentation.calledPresentationSelector.Value[i]
		bufPos++
	}

	// presentation-context-definition-list (Context-specific 4, Constructed) = 0xa4
	bufPos = ber.EncodeTL(ber.ContextSpecific4Constructed, 35, buf, bufPos)

	// ACSE context list item (SEQUENCE) = 0x30
	bufPos = ber.EncodeTL(ber.SequenceConstructed, 15, buf, bufPos)

	// presentation-context-identifier: 1 (INTEGER) = 0x02
	bufPos = ber.EncodeTL(ber.Integer, 1, buf, bufPos)
	buf[bufPos] = 1
	bufPos++

	// abstract-syntax-name: id-as-acse (OBJECT IDENTIFIER) = 0x06
	bufPos = ber.EncodeTL(ber.ObjectIdentifier, 4, buf, bufPos)
	for i := 0; i < 4; i++ {
		buf[bufPos] = asnIDAsACSE[i]
		bufPos++
	}

	// transfer-syntax-name-list (SEQUENCE) = 0x30
	bufPos = ber.EncodeTL(ber.SequenceConstructed, 4, buf, bufPos)
	// Transfer-syntax-name: basic-encoding (OBJECT IDENTIFIER) = 0x06
	bufPos = ber.EncodeTL(ber.ObjectIdentifier, 2, buf, bufPos)
	for i := 0; i < 2; i++ {
		buf[bufPos] = berID[i]
		bufPos++
	}

	// MMS context list item (SEQUENCE) = 0x30
	bufPos = ber.EncodeTL(ber.SequenceConstructed, 16, buf, bufPos)

	// presentation-context-identifier: 3 (INTEGER) = 0x02
	bufPos = ber.EncodeTL(ber.Integer, 1, buf, bufPos)
	buf[bufPos] = 3
	bufPos++

	// abstract-syntax-name: mms-abstract-syntax-version1 (OBJECT IDENTIFIER) = 0x06
	bufPos = ber.EncodeTL(ber.ObjectIdentifier, 5, buf, bufPos)
	for i := 0; i < 5; i++ {
		buf[bufPos] = asnIDMMS[i]
		bufPos++
	}

	// transfer-syntax-name-list (SEQUENCE) = 0x30
	bufPos = ber.EncodeTL(ber.SequenceConstructed, 4, buf, bufPos)
	// Transfer-syntax-name: basic-encoding (OBJECT IDENTIFIER) = 0x06
	bufPos = ber.EncodeTL(ber.ObjectIdentifier, 2, buf, bufPos)
	for i := 0; i < 2; i++ {
		buf[bufPos] = berID[i]
		bufPos++
	}

	// encode user data
	bufPos = encodeUserData(presentation, userData, buf, bufPos, true)

	// Копируем userData
	copy(buf[bufPos:], userData)
	bufPos += len(userData)

	return buf[:bufPos]
}

// BuildCPType создаёт CP-type (Presentation Protocol Data Unit).
// Реализация основана на IsoPresentation_createConnectPdu из C библиотеки (строки 892-901).
// Использует значения по умолчанию, соответствующие createConnectPdu.
func BuildCPType(userData []byte) []byte {
	presentation := NewPresentation()
	return createConnectPdu(presentation, userData)
}
