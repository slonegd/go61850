package mms

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/slonegd/go61850/ber"
	"github.com/slonegd/go61850/osi/mms/variant"
)

// ReadResponse представляет MMS Read Response PDU
// Структура согласно ISO/IEC 9506-2:
//
//	confirmed-ResponsePDU ::= SEQUENCE {
//	  invokeID            [0] IMPLICIT Unsigned32,
//	  confirmedServiceResponse [1] CHOICE {
//	    read [4] Read-Response
//	  }
//	}
//
//	Read-Response ::= SEQUENCE {
//	  variableAccessSpecification [0] VariableAccessSpecification OPTIONAL,
//	  listOfAccessResult [1] SEQUENCE OF AccessResult
//	}
//
//	AccessResult ::= CHOICE {
//	  failure [0] DataAccessError,
//	  success [1] Data
//	}
//
//	Data ::= CHOICE {
//	  array [0] IMPLICIT SEQUENCE OF Data,
//	  structure [1] IMPLICIT SEQUENCE OF Data,
//	  bool [2] IMPLICIT BOOLEAN,
//	  bit-string [4] IMPLICIT BIT STRING,  // Context-specific 4 = 0x84
//	  integer [5] IMPLICIT INTEGER,         // Context-specific 5 = 0x85
//	  unsigned [5] IMPLICIT Unsigned,
//	  floating-point [6] IMPLICIT FloatingPoint,
//	  octet-string [7] IMPLICIT OCTET STRING,
//	  visible-string [8] IMPLICIT VisibleString,
//	  binary-time [9] IMPLICIT BinaryTime,
//	  mmsString [10] IMPLICIT MMSString,
//	  utc-time [11] IMPLICIT UtcTime
//	}
//
//	FloatingPoint ::= OCTET STRING (SIZE (9))
//	Структура: 1 байт (формат: 0x08 для IEEE 754 single precision) + 4 байта (значение float)
type ReadResponse struct {
	InvokeID           uint32
	ListOfAccessResult []AccessResult
}

// AccessResult представляет результат доступа к переменной
type AccessResult struct {
	Success bool
	Value   *variant.Variant // Типизированное значение MMS Data
	Error   *DataAccessError
}

// DataAccessErrorCode представляет код ошибки доступа к данным MMS
// Значения согласно ISO/IEC 9506-2 (MMS) и ASN.1 определению DataAccessError
type DataAccessErrorCode uint32

const (
	// ObjectInvalidated объект был инвалидирован
	ObjectInvalidated DataAccessErrorCode = 0
	// HardwareFault ошибка оборудования
	HardwareFault DataAccessErrorCode = 1
	// TemporarilyUnavailable объект временно недоступен
	TemporarilyUnavailable DataAccessErrorCode = 2
	// ObjectAccessDenied доступ к объекту запрещен
	ObjectAccessDenied DataAccessErrorCode = 3
	// ObjectUndefined объект не определен
	ObjectUndefined DataAccessErrorCode = 4
	// InvalidAddress неверный адрес
	InvalidAddress DataAccessErrorCode = 5
	// TypeUnsupported тип не поддерживается
	TypeUnsupported DataAccessErrorCode = 6
	// TypeInconsistent тип не согласован
	TypeInconsistent DataAccessErrorCode = 7
	// ObjectAttributeInconsistent атрибуты объекта не согласованы
	ObjectAttributeInconsistent DataAccessErrorCode = 8
	// ObjectAccessUnsupported доступ к объекту не поддерживается
	ObjectAccessUnsupported DataAccessErrorCode = 9
	// ObjectNonExistent объект не существует
	ObjectNonExistent DataAccessErrorCode = 10
	// ObjectValueInvalid значение объекта неверно
	ObjectValueInvalid DataAccessErrorCode = 11
)

// String возвращает строковое представление кода ошибки
func (c DataAccessErrorCode) String() string {
	switch c {
	case ObjectInvalidated:
		return "object-invalidated"
	case HardwareFault:
		return "hardware-fault"
	case TemporarilyUnavailable:
		return "temporarily-unavailable"
	case ObjectAccessDenied:
		return "object-access-denied"
	case ObjectUndefined:
		return "object-undefined"
	case InvalidAddress:
		return "invalid-address"
	case TypeUnsupported:
		return "type-unsupported"
	case TypeInconsistent:
		return "type-inconsistent"
	case ObjectAttributeInconsistent:
		return "object-attribute-inconsistent"
	case ObjectAccessUnsupported:
		return "object-access-unsupported"
	case ObjectNonExistent:
		return "object-non-existent"
	case ObjectValueInvalid:
		return "object-value-invalid"
	default:
		return fmt.Sprintf("unknown-error-code-%d", c)
	}
}

// DataAccessError представляет ошибку доступа к данным
type DataAccessError struct {
	ErrorCode DataAccessErrorCode
}

// String возвращает строковое представление ошибки доступа к данным
func (e *DataAccessError) String() string {
	if e == nil {
		return "<nil>"
	}
	return e.ErrorCode.String()
}

// ParseReadResponse парсит MMS Read Response PDU из BER-кодированного буфера
// Структура из wireshark:
// a0 10 - confirmed-ResponsePDU (Context-specific 0, Constructed, длина 16 байт)
//
//	02 01 01 - invokeID (INTEGER, длина 1, значение 1)
//	a4 09 - confirmedServiceResponse: read (Context-specific 4, Constructed, длина 9 байт)
//	   a1 07 - read (Context-specific 1, Constructed, длина 7 байт)
//	      87 05 - listOfAccessResult: success (Context-specific 7, длина 5 байт)
//	         08 3d a8 83 7c - floating-point: формат 0x08 (IEEE 754 single) + 4 байта значения
//
// После установления соединения данные могут приходить без внешнего тега confirmed-ResponsePDU:
// a1 0e - read (Context-specific 1, Constructed, длина 14 байт)
//
//	02 01 01 - invokeID
//	a4 09 - confirmedServiceResponse: read
//	   a1 07 - read
//	      87 05 - success
func ParseReadResponse(buffer []byte) (ReadResponse, error) {
	var response ReadResponse
	if len(buffer) == 0 {
		return response, errors.New("empty buffer")
	}

	// Проверяем формат данных
	// После установления соединения данные могут приходить в разных форматах:
	// 1. Стандартный: a0 (confirmed-ResponsePDU) + length + invokeID + confirmedServiceResponse
	// 2. Без обертки: a1 (read) + length + invokeID + confirmedServiceResponse
	// 3. Прямое содержимое: invokeID + confirmedServiceResponse (без внешних тегов)
	var bufPos int
	var maxBufPos int

	if buffer[0] == 0xA0 {
		// Стандартный формат с тегом confirmed-ResponsePDU
		bufPos = 1
		maxBufPos = len(buffer)

		// Декодируем длину
		newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			return response, fmt.Errorf("failed to decode length: %w", err)
		}
		bufPos = newPos

		// Проверяем, что длина соответствует размеру буфера
		if bufPos+length > maxBufPos {
			return response, errors.New("invalid length: exceeds buffer size")
		}

		maxBufPos = bufPos + length
	} else if buffer[0] == 0xA1 {
		// Данные приходят с тегом read (a1), но внутри содержимое confirmed-ResponsePDU
		// Парсим как confirmed-ResponsePDU, пропуская внешний тег
		bufPos = 1
		maxBufPos = len(buffer)

		// Декодируем длину
		newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			return response, fmt.Errorf("failed to decode length: %w", err)
		}
		bufPos = newPos

		// Проверяем, что длина соответствует размеру буфера
		if bufPos+length > maxBufPos {
			return response, errors.New("invalid length: exceeds buffer size")
		}

		maxBufPos = bufPos + length
	} else {
		// Данные приходят без внешних тегов, парсим содержимое напрямую
		bufPos = 0
		maxBufPos = len(buffer)
	}

	// Парсим поля confirmed-ResponsePDU
	for bufPos < maxBufPos {
		tag := buffer[bufPos]
		bufPos++

		newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			return response, fmt.Errorf("failed to decode length for tag 0x%02x: %w", tag, err)
		}
		bufPos = newPos

		if bufPos+length > maxBufPos {
			return response, fmt.Errorf("invalid length for tag 0x%02x: exceeds buffer size", tag)
		}

		switch tag {
		case 0x02: // invokeID (INTEGER)
			response.InvokeID = ber.DecodeUint32(buffer, length, bufPos)
			bufPos += length

		case 0xA4: // confirmedServiceResponse: read (Context-specific 4, Constructed)
			// Парсим read response
			readResponse, err := parseReadServiceResponse(buffer[bufPos:bufPos+length], length)
			if err != nil {
				return response, fmt.Errorf("failed to parse read service response: %w", err)
			}
			response.ListOfAccessResult = readResponse
			bufPos += length

		default:
			// Пропускаем неизвестные теги
			bufPos += length
		}
	}

	return response, nil
}

// parseReadServiceResponse парсит read service response
// Структура: a1 (read) + length + content
// где content содержит:
//   - 87 (listOfAccessResult: success) + length + floating-point value
func parseReadServiceResponse(buffer []byte, maxLength int) ([]AccessResult, error) {
	if len(buffer) == 0 {
		return nil, errors.New("empty buffer")
	}

	// Проверяем, что это read (tag 0xA1)
	if buffer[0] != 0xA1 {
		return nil, fmt.Errorf("invalid tag: expected 0xA1 (read), got 0x%02x", buffer[0])
	}

	bufPos := 1
	maxBufPos := len(buffer)
	if maxLength < maxBufPos {
		maxBufPos = maxLength
	}

	// Декодируем длину
	newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
	if err != nil {
		return nil, fmt.Errorf("failed to decode length: %w", err)
	}
	bufPos = newPos

	if bufPos+length > maxBufPos {
		return nil, errors.New("invalid length: exceeds buffer size")
	}

	maxBufPos = bufPos + length

	var results []AccessResult

	// Парсим listOfAccessResult (SEQUENCE OF AccessResult)
	// В wireshark видно, что listOfAccessResult может быть закодирован напрямую как success (tag 0x87)
	// или как SEQUENCE (tag 0x30) с элементами
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
		case 0x30: // SEQUENCE (listOfAccessResult)
			// Парсим элементы SEQUENCE
			seqResults, err := parseListOfAccessResult(buffer[bufPos:bufPos+length], length)
			if err != nil {
				return nil, fmt.Errorf("failed to parse listOfAccessResult: %w", err)
			}
			results = append(results, seqResults...)
			bufPos += length

		case 0x87: // success (Context-specific 7) - floating-point
			// Парсим floating-point значение
			value, err := parseFloatingPoint(buffer[bufPos:bufPos+length], length)
			if err != nil {
				return nil, fmt.Errorf("failed to parse floating-point: %w", err)
			}
			results = append(results, AccessResult{
				Success: true,
				Value:   variant.NewFloat32Variant(value),
			})
			bufPos += length

		case 0x84: // success (Context-specific 4) - bit-string
			// Парсим bit-string значение
			value, err := parseBitString(buffer[bufPos:bufPos+length], length)
			if err != nil {
				return nil, fmt.Errorf("failed to parse bit-string: %w", err)
			}
			results = append(results, AccessResult{
				Success: true,
				Value:   value,
			})
			bufPos += length

		case 0x85: // success (Context-specific 5) - integer
			// Парсим integer значение
			value, err := parseInteger(buffer[bufPos:bufPos+length], length)
			if err != nil {
				return nil, fmt.Errorf("failed to parse integer: %w", err)
			}
			results = append(results, AccessResult{
				Success: true,
				Value:   variant.NewInt32Variant(value),
			})
			bufPos += length

		case 0x91: // success (Context-specific 17) - utc-time
			// Парсим UTC time значение
			value, err := parseUTCTime(buffer[bufPos:bufPos+length], length)
			if err != nil {
				return nil, fmt.Errorf("failed to parse utc-time: %w", err)
			}
			results = append(results, AccessResult{
				Success: true,
				Value:   variant.NewUTCTimeVariant(value),
			})
			bufPos += length

		case 0x80: // failure (Context-specific 0) - DataAccessError
			// Парсим ошибку доступа к данным
			errorCode := DataAccessErrorCode(ber.DecodeUint32(buffer, length, bufPos))
			results = append(results, AccessResult{
				Success: false,
				Error: &DataAccessError{
					ErrorCode: errorCode,
				},
			})
			bufPos += length

		default:
			// Неподдерживаемый тег - возвращаем ошибку с указанием номера тега
			return nil, fmt.Errorf("unsupported tag: 0x%02x", tag)
		}
	}

	return results, nil
}

// parseListOfAccessResult парсит SEQUENCE OF AccessResult
func parseListOfAccessResult(buffer []byte, maxLength int) ([]AccessResult, error) {
	var results []AccessResult

	bufPos := 0
	maxBufPos := len(buffer)
	if maxLength < maxBufPos {
		maxBufPos = maxLength
	}

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
		case 0x87: // success (Context-specific 7) - floating-point
			value, err := parseFloatingPoint(buffer[bufPos:bufPos+length], length)
			if err != nil {
				return nil, fmt.Errorf("failed to parse floating-point: %w", err)
			}
			results = append(results, AccessResult{
				Success: true,
				Value:   variant.NewFloat32Variant(value),
			})
			bufPos += length

		case 0x84: // success (Context-specific 4) - bit-string
			// Парсим bit-string значение
			value, err := parseBitString(buffer[bufPos:bufPos+length], length)
			if err != nil {
				return nil, fmt.Errorf("failed to parse bit-string: %w", err)
			}
			results = append(results, AccessResult{
				Success: true,
				Value:   value,
			})
			bufPos += length

		case 0x85: // success (Context-specific 5) - integer
			// Парсим integer значение
			value, err := parseInteger(buffer[bufPos:bufPos+length], length)
			if err != nil {
				return nil, fmt.Errorf("failed to parse integer: %w", err)
			}
			results = append(results, AccessResult{
				Success: true,
				Value:   variant.NewInt32Variant(value),
			})
			bufPos += length

		case 0x91: // success (Context-specific 17) - utc-time
			// Парсим UTC time значение
			value, err := parseUTCTime(buffer[bufPos:bufPos+length], length)
			if err != nil {
				return nil, fmt.Errorf("failed to parse utc-time: %w", err)
			}
			results = append(results, AccessResult{
				Success: true,
				Value:   variant.NewUTCTimeVariant(value),
			})
			bufPos += length

		case 0x80: // failure (Context-specific 0) - DataAccessError
			// Парсим ошибку
			errorCode := DataAccessErrorCode(ber.DecodeUint32(buffer, length, bufPos))
			results = append(results, AccessResult{
				Success: false,
				Error: &DataAccessError{
					ErrorCode: errorCode,
				},
			})
			bufPos += length

		default:
			// Неподдерживаемый тег - возвращаем ошибку с указанием номера тега
			return nil, fmt.Errorf("unsupported tag: 0x%02x", tag)
		}
	}

	return results, nil
}

// parseFloatingPoint парсит floating-point значение
// Структура: 1 байт (формат) + 4 байта (значение IEEE 754 single precision)
// Формат: 0x08 для IEEE 754 single precision (32-bit float)
func parseFloatingPoint(buffer []byte, length int) (float32, error) {
	if length < 5 {
		return 0, fmt.Errorf("invalid floating-point length: expected at least 5 bytes, got %d", length)
	}

	format := buffer[0]
	if format != 0x08 {
		return 0, fmt.Errorf("unsupported floating-point format: expected 0x08 (IEEE 754 single), got 0x%02x", format)
	}

	// Извлекаем 4 байта значения (IEEE 754 single precision)
	// Байты идут в порядке big-endian
	bits := binary.BigEndian.Uint32(buffer[1:5])
	value := math.Float32frombits(bits)

	return value, nil
}

// parseInteger парсит integer значение
// INTEGER в BER кодируется как signed integer в big-endian формате
// Длина может быть от 1 до 4 байт для 32-bit integer
func parseInteger(buffer []byte, length int) (int32, error) {
	if length < 1 {
		return 0, fmt.Errorf("invalid integer length: expected at least 1 byte, got %d", length)
	}
	if length > 4 {
		return 0, fmt.Errorf("invalid integer length: expected at most 4 bytes for int32, got %d", length)
	}

	// Используем ber.DecodeInt32 для декодирования signed integer
	// bufPos = 0, так как buffer уже является срезом с нужными данными
	value := ber.DecodeInt32(buffer, length, 0)

	return value, nil
}

// parseBitString парсит bit-string значение
// Структура согласно ISO/IEC 9506-2:
// - 1 байт: padding (количество неиспользуемых бит в последнем байте, 0-7)
// - N байт: данные bit-string
// Основано на mms_access_result.c case 0x84
func parseBitString(buffer []byte, length int) (*variant.Variant, error) {
	if length < 1 {
		return nil, fmt.Errorf("invalid bit-string length: expected at least 1 byte, got %d", length)
	}

	padding := int(buffer[0])
	if padding > 7 {
		return nil, fmt.Errorf("invalid bit-string padding: expected 0-7, got %d", padding)
	}

	// Данные начинаются со второго байта
	dataLength := length - 1
	if dataLength < 0 {
		return nil, fmt.Errorf("invalid bit-string length: no data bytes")
	}

	data := make([]byte, dataLength)
	copy(data, buffer[1:1+dataLength])

	// Вычисляем количество значащих бит
	bitSize := (8 * dataLength) - padding

	return variant.NewBitStringVariant(data, bitSize), nil
}

// parseUTCTime парсит UTC time значение
// Структура согласно ISO/IEC 9506-2:
// - 4 байта: секунды с 1 января 1970 00:00:00 UTC (big-endian uint32)
// - 3 байта: доля секунды (fraction of second) в единицах 1/2^24 секунды
// - 1 байт: качество времени (time quality)
// Итого 8 байт
// Основано на MmsValue_getUtcTimeInMsWithUs из mms_value.c
func parseUTCTime(buffer []byte, length int) (time.Time, error) {
	if length != 8 {
		return time.Time{}, fmt.Errorf("invalid utc-time length: expected 8 bytes, got %d", length)
	}

	// Декодируем секунды (первые 4 байта, big-endian)
	seconds := binary.BigEndian.Uint32(buffer[0:4])

	// Декодируем долю секунды (байты 4-6)
	// fractionOfSecond в единицах 1/2^24 секунды
	fractionOfSecond := uint32(buffer[4])<<16 | uint32(buffer[5])<<8 | uint32(buffer[6])

	// Преобразуем долю секунды в наносекунды
	// fractionOfSecond * 1_000_000_000 / 2^24
	// Используем uint64 для избежания переполнения
	nanoseconds := uint64(fractionOfSecond) * 1_000_000_000 / 0x1000000

	// Качество времени (байт 7) игнорируем, так как оно не влияет на значение времени

	// Создаём time.Time из секунд и наносекунд
	t := time.Unix(int64(seconds), int64(nanoseconds)).UTC()

	return t, nil
}

// String возвращает строковое представление ReadResponse
func (r *ReadResponse) String() string {
	if len(r.ListOfAccessResult) == 0 {
		return fmt.Sprintf("ReadResponse{InvokeID: %d, Results: []}", r.InvokeID)
	}

	var results []string
	for i, result := range r.ListOfAccessResult {
		if result.Success {
			if result.Value == nil {
				results = append(results, fmt.Sprintf("Result[%d]: <nil>", i))
			} else {
				switch result.Value.Type() {
				case variant.Float32:
					val := result.Value.Float32()
					results = append(results, fmt.Sprintf("Result[%d]: %f", i, val))
				case variant.Int32:
					val := result.Value.Int32()
					results = append(results, fmt.Sprintf("Result[%d]: %d", i, val))
				case variant.UTCTime:
					val := result.Value.Time()
					results = append(results, fmt.Sprintf("Result[%d]: %s", i, val.Format(time.RFC3339Nano)))
				case variant.BitString:
					val := result.Value.BitString()
					results = append(results, fmt.Sprintf("Result[%d]: bit-string(%d bits)", i, val.BitSize))
				default:
					results = append(results, fmt.Sprintf("Result[%d]: <unknown type: %v>", i, result.Value.Type()))
				}
			}
		} else {
			if result.Error != nil {
				results = append(results, fmt.Sprintf("Result[%d]: Error(%s)", i, result.Error.ErrorCode))
			} else {
				results = append(results, fmt.Sprintf("Result[%d]: Error(<nil>)", i))
			}
		}
	}

	return fmt.Sprintf("ReadResponse{InvokeID: %d, Results: [%s]}", r.InvokeID, fmt.Sprint(results))
}
