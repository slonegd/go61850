package mms

import (
	"errors"
	"fmt"
	"strings"

	"github.com/slonegd/go61850/ber"
)

// InitiateResponse содержит параметры из MMS Initiate Response PDU
type InitiateResponse struct {
	// LocalDetailCalled - максимальный размер PDU (в байтах), согласованный сервером
	LocalDetailCalled *uint32
	// NegotiatedMaxServOutstandingCalling - максимальное количество одновременных запросов от клиента, согласованное сервером
	NegotiatedMaxServOutstandingCalling uint32
	// NegotiatedMaxServOutstandingCalled - максимальное количество одновременных запросов к серверу, согласованное сервером
	NegotiatedMaxServOutstandingCalled uint32
	// NegotiatedDataStructureNestingLevel - максимальный уровень вложенности структур данных, согласованный сервером
	NegotiatedDataStructureNestingLevel *uint32
	// NegotiatedVersionNumber - версия протокола MMS, согласованная сервером
	NegotiatedVersionNumber uint32
	// NegotiatedParameterCBB - поддерживаемые параметры, согласованные сервером (слайс битов)
	NegotiatedParameterCBB []ParameterCBBBit
	// ServicesSupportedCalled - поддерживаемые услуги, согласованные сервером (слайс битов)
	ServicesSupportedCalled []ServiceSupportedBit
}

// String реализует интерфейс fmt.Stringer для InitiateResponse.
// Для NegotiatedParameterCBB и ServicesSupportedCalled выводит список установленных битов,
// остальные поля выводятся как при %+v.
func (r *InitiateResponse) String() string {
	var parts []string

	if r.LocalDetailCalled != nil {
		parts = append(parts, fmt.Sprintf("LocalDetailCalled:%d", *r.LocalDetailCalled))
	} else {
		parts = append(parts, "LocalDetailCalled:<nil>")
	}
	parts = append(parts, fmt.Sprintf("NegotiatedMaxServOutstandingCalling:%d", r.NegotiatedMaxServOutstandingCalling))
	parts = append(parts, fmt.Sprintf("NegotiatedMaxServOutstandingCalled:%d", r.NegotiatedMaxServOutstandingCalled))
	if r.NegotiatedDataStructureNestingLevel != nil {
		parts = append(parts, fmt.Sprintf("NegotiatedDataStructureNestingLevel:%d", *r.NegotiatedDataStructureNestingLevel))
	} else {
		parts = append(parts, "NegotiatedDataStructureNestingLevel:<nil>")
	}
	parts = append(parts, fmt.Sprintf("NegotiatedVersionNumber:%d", r.NegotiatedVersionNumber))

	// NegotiatedParameterCBB - список установленных битов
	if len(r.NegotiatedParameterCBB) > 0 {
		bitNames := make([]string, len(r.NegotiatedParameterCBB))
		for i, bit := range r.NegotiatedParameterCBB {
			bitNames[i] = bit.String()
		}
		parts = append(parts, fmt.Sprintf("NegotiatedParameterCBB:[%s]", strings.Join(bitNames, " ")))
	} else {
		parts = append(parts, "NegotiatedParameterCBB:[]")
	}

	// ServicesSupportedCalled - список установленных битов
	if len(r.ServicesSupportedCalled) > 0 {
		bitNames := make([]string, len(r.ServicesSupportedCalled))
		for i, bit := range r.ServicesSupportedCalled {
			bitNames[i] = bit.String()
		}
		parts = append(parts, fmt.Sprintf("ServicesSupportedCalled:[%s]", strings.Join(bitNames, " ")))
	} else {
		parts = append(parts, "ServicesSupportedCalled:[]")
	}

	return fmt.Sprintf("InitiateResponse{%s}", strings.Join(parts, " "))
}

// ParseInitiateResponse парсит BER-кодированный MMS Initiate Response PDU.
// Структура пакета (из libIEC61850):
//
//	A9 (tag) + length + content
//	где content содержит:
//	  - 80 (localDetailCalled) + length + value (опционально)
//	  - 81 (negotiatedMaxServOutstandingCalling) + length + value
//	  - 82 (negotiatedMaxServOutstandingCalled) + length + value
//	  - 83 (negotiatedDataStructureNestingLevel) + length + value (опционально)
//	  - A4 (mmsInitResponseDetail) + length + detail_content
//	    где detail_content содержит:
//	      - 80 (negotiatedVersionNumber) + length + value
//	      - 81 (negotiatedParameterCBB) + length + padding + bit_string
//	      - 82 (servicesSupportedCalled) + length + padding + bit_string
func ParseInitiateResponse(buffer []byte) (*InitiateResponse, error) {
	if len(buffer) == 0 {
		return nil, errors.New("empty buffer")
	}

	// Проверяем, что это InitiateResponsePDU (tag 0xA9)
	if buffer[0] != 0xA9 {
		return nil, fmt.Errorf("invalid tag: expected 0xA9, got 0x%02x", buffer[0])
	}

	response := &InitiateResponse{}

	bufPos := 1
	maxBufPos := len(buffer)

	// Декодируем длину
	newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
	if err != nil {
		return nil, fmt.Errorf("failed to decode length: %w", err)
	}
	bufPos = newPos

	// Проверяем, что длина соответствует размеру буфера
	if bufPos+length > maxBufPos {
		return nil, errors.New("invalid length: exceeds buffer size")
	}

	maxBufPos = bufPos + length

	// Парсим поля InitiateResponsePDU
	for bufPos < maxBufPos {
		tag := buffer[bufPos]
		bufPos++

		newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			return nil, fmt.Errorf("failed to decode length for tag 0x%02x: %w", tag, err)
		}
		bufPos = newPos

		if bufPos+length > maxBufPos {
			return nil, fmt.Errorf("invalid length for tag 0x%02x: exceeds buffer size", tag)
		}

		switch tag {
		case 0x80: // localDetailCalled (опционально)
			value := ber.DecodeUint32(buffer, length, bufPos)
			response.LocalDetailCalled = &value
			bufPos += length

		case 0x81: // negotiatedMaxServOutstandingCalling
			response.NegotiatedMaxServOutstandingCalling = ber.DecodeUint32(buffer, length, bufPos)
			bufPos += length

		case 0x82: // negotiatedMaxServOutstandingCalled
			response.NegotiatedMaxServOutstandingCalled = ber.DecodeUint32(buffer, length, bufPos)
			bufPos += length

		case 0x83: // negotiatedDataStructureNestingLevel (опционально)
			value := ber.DecodeUint32(buffer, length, bufPos)
			response.NegotiatedDataStructureNestingLevel = &value
			bufPos += length

		case 0xA4: // mmsInitResponseDetail
			detailStart := bufPos
			detailEnd := bufPos + length

			// Парсим поля mmsInitResponseDetail
			for detailStart < detailEnd {
				detailTag := buffer[detailStart]
				detailStart++

				newPos, detailLength, err := ber.DecodeLength(buffer, detailStart, detailEnd)
				if err != nil {
					return nil, fmt.Errorf("failed to decode length for detail tag 0x%02x: %w", detailTag, err)
				}
				detailStart = newPos

				if detailStart+detailLength > detailEnd {
					return nil, fmt.Errorf("invalid length for detail tag 0x%02x: exceeds buffer size", detailTag)
				}

				switch detailTag {
				case 0x80: // negotiatedVersionNumber
					response.NegotiatedVersionNumber = ber.DecodeUint32(buffer, detailLength, detailStart)
					detailStart += detailLength

				case 0x81: // negotiatedParameterCBB (BIT STRING)
					// Первый байт - количество неиспользуемых бит (padding)
					if detailLength < 1 {
						return nil, errors.New("invalid negotiatedParameterCBB: missing padding byte")
					}
					paddingBits := buffer[detailStart]
					detailStart++

					// Остальные байты - битовая маска
					bitmaskBytes := detailLength - 1
					if bitmaskBytes > 0 {
						bitmask := buffer[detailStart : detailStart+bitmaskBytes]
						offsets := ber.DecodeBitmaskFromBytes(bitmask, paddingBits, ProposedParameterCBBBitmaskSize)
						// Конвертируем offsets в ParameterCBBBit
						response.NegotiatedParameterCBB = make([]ParameterCBBBit, 0, len(offsets))
						for _, offset := range offsets {
							if offset < uint(Cei)+1 {
								response.NegotiatedParameterCBB = append(response.NegotiatedParameterCBB, ParameterCBBBit(offset))
							}
						}
					}
					detailStart += bitmaskBytes

				case 0x82: // servicesSupportedCalled (BIT STRING)
					// Первый байт - количество неиспользуемых бит (padding)
					if detailLength < 1 {
						return nil, errors.New("invalid servicesSupportedCalled: missing padding byte")
					}
					paddingBits := buffer[detailStart]
					detailStart++

					// Остальные байты - битовая маска
					bitmaskBytes := detailLength - 1
					if bitmaskBytes > 0 {
						bitmask := buffer[detailStart : detailStart+bitmaskBytes]
						offsets := ber.DecodeBitmaskFromBytes(bitmask, paddingBits, ServicesSupportedCallingBitmaskSize)
						// Конвертируем offsets в ServiceSupportedBit
						response.ServicesSupportedCalled = make([]ServiceSupportedBit, 0, len(offsets))
						for _, offset := range offsets {
							if offset < uint(Cancel)+1 {
								response.ServicesSupportedCalled = append(response.ServicesSupportedCalled, ServiceSupportedBit(offset))
							}
						}
					}
					detailStart += bitmaskBytes

				case 0x00: // indefinite length end tag -> ignore
					break

				default:
					// Игнорируем неизвестные теги
					detailStart += detailLength
				}
			}
			bufPos += length

		case 0x00: // indefinite length end tag -> ignore
			break

		default:
			// Игнорируем неизвестные теги
			bufPos += length
		}
	}

	return response, nil
}
