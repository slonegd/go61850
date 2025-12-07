package presentation

import (
	"errors"
	"fmt"
	"strings"

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

// PresentationPDUType представляет тип Presentation PDU
type PresentationPDUType uint8

const (
	CP  PresentationPDUType = 0x31 // CP-type (Connect Presentation)
	CPA PresentationPDUType = 0x31 // CPA-PPDU (Connect Presentation Accept) - тот же тег
)

// PresentationPDU представляет Presentation Protocol Data Unit (ISO 8823)
type PresentationPDU struct {
	Type                           PresentationPDUType // Тип PDU (0x31 для CP/CPA)
	ModeValue                      uint8               // Mode value (1 = normal-mode)
	RespondingPresentationSelector []byte              // Responding Presentation Selector (в CPA)
	CallingPresentationSelector    []byte              // Calling Presentation Selector (в CP)
	CalledPresentationSelector     []byte              // Called Presentation Selector (в CP)
	AcseContextId                  uint8               // ACSE context identifier
	MmsContextId                   uint8               // MMS context identifier
	PresentationContextId          uint8               // Presentation context identifier из user-data (например, 1 = id-as-acse)
	PresentationDataValuesType     uint8               // Presentation data values type (0 = single-ASN1-type)
	Data                           []byte              // Данные следующего уровня (ACSE)
}

// parseFullyEncodedData парсит fully-encoded-data согласно parseFullyEncodedData из C библиотеки (строки 191-279)
// Возвращает: newPos, contextId, dataValuesType (0 = single-ASN1-type), data, error
func parseFullyEncodedData(buffer []byte, bufPos, maxBufPos int) (newPos int, contextId uint8, dataValuesType uint8, data []byte, err error) {
	if bufPos >= maxBufPos {
		return -1, 0, 0, nil, errors.New("buffer overflow")
	}

	if buffer[bufPos] != 0x30 { // SEQUENCE
		return -1, 0, 0, nil, errors.New("expected SEQUENCE in fully-encoded-data")
	}
	bufPos++

	newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
	if err != nil {
		return -1, 0, 0, nil, fmt.Errorf("failed to decode length: %w", err)
	}
	bufPos = newPos

	endPos := bufPos + length
	contextId = 0
	dataValuesType = 0
	data = nil
	userDataPresent := false

	for bufPos < endPos {
		if bufPos >= maxBufPos {
			break
		}

		tag := buffer[bufPos]
		bufPos++

		if bufPos >= maxBufPos {
			break
		}

		newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			return -1, 0, 0, nil, fmt.Errorf("failed to decode length: %w", err)
		}
		bufPos = newPos

		switch tag {
		case 0x02: // presentation-context-identifier (INTEGER)
			if length > 0 && bufPos < maxBufPos {
				contextId = buffer[bufPos]
				bufPos += length
			} else {
				bufPos += length
			}
		case 0x06: // transfer-syntax-name (OBJECT IDENTIFIER)
			bufPos += length
		case 0xa0: // presentation-data-values: single-ASN1-type (0) (Context-specific 0, Constructed)
			// Тег 0xa0 означает Context-specific 0, Constructed, что соответствует single-ASN1-type (0)
			dataValuesType = 0
			if bufPos+length <= maxBufPos {
				data = make([]byte, length)
				copy(data, buffer[bufPos:bufPos+length])
				userDataPresent = true
				bufPos += length
			} else {
				bufPos += length
			}
		case 0x00: // indefinite length end tag
			// ignore
		default:
			bufPos += length
		}
	}

	if !userDataPresent {
		return -1, 0, 0, nil, errors.New("user-data not present")
	}

	return bufPos, contextId, dataValuesType, data, nil
}

// parseNormalModeParameters парсит normal-mode-parameters согласно parseNormalModeParameters из C библиотеки (строки 414-543)
func parseNormalModeParameters(buffer []byte, bufPos, maxBufPos int) (newPos int, pdu *PresentationPDU, err error) {
	pdu = &PresentationPDU{}

	newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
	if err != nil {
		return -1, nil, fmt.Errorf("failed to decode normal-mode-parameters length: %w", err)
	}
	bufPos = newPos

	endPos := bufPos + length
	if endPos > maxBufPos {
		endPos = maxBufPos
	}
	hasUserData := false

	for bufPos < endPos && bufPos < maxBufPos {

		tag := buffer[bufPos]
		bufPos++

		if bufPos >= maxBufPos {
			break
		}

		newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			return -1, nil, fmt.Errorf("failed to decode parameter length: %w", err)
		}
		bufPos = newPos

		switch tag {
		case 0x81: // calling-presentation-selector (Context-specific 1, OCTET STRING)
			if length > 0 && length <= 16 && bufPos+length <= maxBufPos {
				pdu.CallingPresentationSelector = make([]byte, length)
				copy(pdu.CallingPresentationSelector, buffer[bufPos:bufPos+length])
				bufPos += length
			} else {
				bufPos += length
			}
		case 0x82: // called-presentation-selector (Context-specific 2, OCTET STRING)
			if length > 0 && length <= 16 && bufPos+length <= maxBufPos {
				pdu.CalledPresentationSelector = make([]byte, length)
				copy(pdu.CalledPresentationSelector, buffer[bufPos:bufPos+length])
				bufPos += length
			} else {
				bufPos += length
			}
		case 0x83: // responding-presentation-selector (Context-specific 3, OCTET STRING)
			if length > 0 && length <= 16 && bufPos+length <= maxBufPos {
				pdu.RespondingPresentationSelector = make([]byte, length)
				copy(pdu.RespondingPresentationSelector, buffer[bufPos:bufPos+length])
				bufPos += length
			} else {
				bufPos += length
			}
		case 0xa4: // presentation-context-definition-list (Context-specific 4, Constructed) - в CP-type
		case 0xa5: // context-definition-result-list (Context-specific 5, Constructed) - в CPA-PPDU
			// Парсим список контекстов для определения acseContextId и mmsContextId
			contextListEnd := bufPos + length
			for bufPos < contextListEnd && bufPos < maxBufPos {
				if buffer[bufPos] != 0x30 { // SEQUENCE
					bufPos++
					continue
				}
				bufPos++

				newPos, seqLength, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
				if err != nil {
					bufPos = contextListEnd
					break
				}
				bufPos = newPos

				seqEnd := bufPos + seqLength
				contextId := uint8(0)
				isAcse := false
				isMms := false

				for bufPos < seqEnd && bufPos < maxBufPos {
					seqTag := buffer[bufPos]
					bufPos++

					if bufPos >= maxBufPos {
						break
					}

					newPos, seqTagLength, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
					if err != nil {
						bufPos = seqEnd
						break
					}
					bufPos = newPos

					switch seqTag {
					case 0x02: // presentation-context-identifier
						if seqTagLength > 0 && bufPos < maxBufPos {
							contextId = buffer[bufPos]
							bufPos += seqTagLength
						} else {
							bufPos += seqTagLength
						}
					case 0x06: // abstract-syntax-name
						if seqTagLength == 4 && bufPos+4 <= maxBufPos {
							// Проверяем на ACSE OID
							if buffer[bufPos] == 0x52 && buffer[bufPos+1] == 0x01 &&
								buffer[bufPos+2] == 0x00 && buffer[bufPos+3] == 0x01 {
								isAcse = true
							}
						}
						if seqTagLength == 5 && bufPos+5 <= maxBufPos {
							// Проверяем на MMS OID
							if buffer[bufPos] == 0x28 && buffer[bufPos+1] == 0xca &&
								buffer[bufPos+2] == 0x22 && buffer[bufPos+3] == 0x02 &&
								buffer[bufPos+4] == 0x01 {
								isMms = true
							}
						}
						bufPos += seqTagLength
					case 0x30: // transfer-syntax-name-list
						bufPos += seqTagLength
					default:
						bufPos += seqTagLength
					}
				}

				if isAcse {
					pdu.AcseContextId = contextId
				}
				if isMms {
					pdu.MmsContextId = contextId
				}
			}
			bufPos = contextListEnd
		case 0x61: // user-data (Application 1, Constructed) - fully-encoded-data
			newPos, contextId, dataValuesType, data, err := parseFullyEncodedData(buffer, bufPos, maxBufPos)
			if err != nil {
				return -1, nil, fmt.Errorf("failed to parse fully-encoded-data: %w", err)
			}
			pdu.PresentationContextId = contextId
			pdu.PresentationDataValuesType = dataValuesType
			pdu.Data = data
			hasUserData = true
			bufPos = newPos
		case 0x00: // indefinite length end tag
			// ignore
		default:
			bufPos += length
		}
	}

	if !hasUserData {
		return -1, nil, errors.New("user-data is missing")
	}

	return bufPos, pdu, nil
}

// ParsePresentationPDU парсит Presentation PDU из байтового буфера
// Реализация основана на IsoPresentation_parseAcceptMessage из C библиотеки (строки 545-612)
func ParsePresentationPDU(data []byte) (*PresentationPDU, error) {
	if len(data) < 1 {
		return nil, errors.New("Presentation PDU too short: need at least 1 byte")
	}

	cpTag := data[0]
	if cpTag != 0x31 {
		return nil, fmt.Errorf("not a CP/CPA message: expected 0x31, got 0x%02x", cpTag)
	}

	pdu := &PresentationPDU{
		Type: PresentationPDUType(cpTag),
	}

	bufPos := 1
	maxBufPos := len(data)

	// Декодируем длину CP-type (пропускаем, так как парсим по тегам)
	newPos, _, err := ber.DecodeLength(data, bufPos, maxBufPos)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CP-type length: %w", err)
	}
	bufPos = newPos

	// Парсим содержимое
	for bufPos < maxBufPos {
		if bufPos >= maxBufPos {
			break
		}

		tag := data[bufPos]
		bufPos++

		if bufPos >= maxBufPos {
			break
		}

		lengthStartPos := bufPos
		newPos, length, err := ber.DecodeLength(data, bufPos, maxBufPos)
		if err != nil {
			return nil, fmt.Errorf("failed to decode parameter length: %w", err)
		}
		bufPos = newPos

		switch tag {
		case 0xa0: // mode-selector (Context-specific 0, Constructed)
			// Парсим mode-value
			if bufPos < maxBufPos && data[bufPos] == 0x80 {
				bufPos++
				newPos, modeLength, err := ber.DecodeLength(data, bufPos, maxBufPos)
				if err == nil && modeLength > 0 && newPos < maxBufPos {
					pdu.ModeValue = data[newPos]
					bufPos = newPos + modeLength
				} else {
					bufPos += length
				}
			} else {
				bufPos += length
			}
		case 0xa2: // normal-mode-parameters (Context-specific 2, Constructed)
			// parseNormalModeParameters ожидает bufPos на позиции длины (после тега)
			// lengthStartPos указывает на позицию длины
			newPos, parsedPdu, err := parseNormalModeParameters(data, lengthStartPos, maxBufPos)
			if err != nil {
				return nil, fmt.Errorf("error parsing normal-mode-parameters: %w", err)
			}
			// Копируем поля из распарсенного PDU
			pdu.RespondingPresentationSelector = parsedPdu.RespondingPresentationSelector
			pdu.CallingPresentationSelector = parsedPdu.CallingPresentationSelector
			pdu.CalledPresentationSelector = parsedPdu.CalledPresentationSelector
			pdu.AcseContextId = parsedPdu.AcseContextId
			pdu.MmsContextId = parsedPdu.MmsContextId
			pdu.PresentationContextId = parsedPdu.PresentationContextId
			pdu.PresentationDataValuesType = parsedPdu.PresentationDataValuesType
			pdu.Data = parsedPdu.Data
			bufPos = newPos
		case 0x00: // indefinite length end tag
			// ignore
		default:
			bufPos += length
		}
	}

	return pdu, nil
}

// String реализует интерфейс fmt.Stringer для PresentationPDU
func (p *PresentationPDU) String() string {
	var builder strings.Builder

	typeStr := "CPA-PPDU"
	if len(p.CallingPresentationSelector) > 0 || len(p.CalledPresentationSelector) > 0 {
		typeStr = "CP-type"
	}

	// Форматируем селекторы в hex
	formatSelector := func(sel []byte) string {
		if len(sel) == 0 {
			return "[]"
		}
		var selBuilder strings.Builder
		selBuilder.WriteByte('[')
		for i, b := range sel {
			if i > 0 {
				selBuilder.WriteByte(' ')
			}
			fmt.Fprintf(&selBuilder, "%02x", b)
		}
		selBuilder.WriteByte(']')
		return selBuilder.String()
	}

	builder.WriteString("PresentationPDU{Type: ")
	builder.WriteString(typeStr)
	fmt.Fprintf(&builder, " (0x%02x)", uint8(p.Type))

	if p.ModeValue != 0 {
		fmt.Fprintf(&builder, ", ModeValue: %d", p.ModeValue)
	}

	if len(p.RespondingPresentationSelector) > 0 {
		builder.WriteString(", RespondingPresentationSelector: ")
		builder.WriteString(formatSelector(p.RespondingPresentationSelector))
	}

	if len(p.CallingPresentationSelector) > 0 {
		builder.WriteString(", CallingPresentationSelector: ")
		builder.WriteString(formatSelector(p.CallingPresentationSelector))
	}

	if len(p.CalledPresentationSelector) > 0 {
		builder.WriteString(", CalledPresentationSelector: ")
		builder.WriteString(formatSelector(p.CalledPresentationSelector))
	}

	if p.AcseContextId != 0 {
		fmt.Fprintf(&builder, ", AcseContextId: %d", p.AcseContextId)
	}

	if p.MmsContextId != 0 {
		fmt.Fprintf(&builder, ", MmsContextId: %d", p.MmsContextId)
	}

	if p.PresentationContextId != 0 {
		// Показываем числовое и символьное значение
		contextName := ""
		if p.PresentationContextId == 1 {
			contextName = "id-as-acse"
		} else if p.PresentationContextId == 3 {
			contextName = "mms-abstract-syntax-version1"
		}
		if contextName != "" {
			fmt.Fprintf(&builder, ", PresentationContextId: %d (%s)", p.PresentationContextId, contextName)
		} else {
			fmt.Fprintf(&builder, ", PresentationContextId: %d", p.PresentationContextId)
		}
	}

	if p.PresentationDataValuesType == 0 {
		// 0 = single-ASN1-type
		fmt.Fprintf(&builder, ", PresentationDataValuesType: %d (single-ASN1-type)", p.PresentationDataValuesType)
	} else {
		fmt.Fprintf(&builder, ", PresentationDataValuesType: %d", p.PresentationDataValuesType)
	}

	fmt.Fprintf(&builder, ", DataLength: %d}", len(p.Data))

	return builder.String()
}

