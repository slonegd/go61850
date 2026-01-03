package mms

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/slonegd/go61850/ber"
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
//	  bit-string [3] IMPLICIT BIT STRING,
//	  integer [4] IMPLICIT INTEGER,
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
	Value   interface{} // Может быть float32, int32, bool, string и т.д.
	Error   *DataAccessError
}

// DataAccessError представляет ошибку доступа к данным
type DataAccessError struct {
	ErrorCode uint32
}

// ParseReadResponse парсит MMS Read Response PDU из BER-кодированного буфера
// Структура из wireshark:
// a0 10 - confirmed-ResponsePDU (Context-specific 0, Constructed, длина 16 байт)
//   02 01 01 - invokeID (INTEGER, длина 1, значение 1)
//   a4 09 - confirmedServiceResponse: read (Context-specific 4, Constructed, длина 9 байт)
//      a1 07 - read (Context-specific 1, Constructed, длина 7 байт)
//         87 05 - listOfAccessResult: success (Context-specific 7, длина 5 байт)
//            08 3d a8 83 7c - floating-point: формат 0x08 (IEEE 754 single) + 4 байта значения
// 
// После установления соединения данные могут приходить без внешнего тега confirmed-ResponsePDU:
// a1 0e - read (Context-specific 1, Constructed, длина 14 байт)
//   02 01 01 - invokeID
//   a4 09 - confirmedServiceResponse: read
//      a1 07 - read
//         87 05 - success
func ParseReadResponse(buffer []byte) (*ReadResponse, error) {
	if len(buffer) == 0 {
		return nil, errors.New("empty buffer")
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
			return nil, fmt.Errorf("failed to decode length: %w", err)
		}
		bufPos = newPos

		// Проверяем, что длина соответствует размеру буфера
		if bufPos+length > maxBufPos {
			return nil, errors.New("invalid length: exceeds buffer size")
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
			return nil, fmt.Errorf("failed to decode length: %w", err)
		}
		bufPos = newPos

		// Проверяем, что длина соответствует размеру буфера
		if bufPos+length > maxBufPos {
			return nil, errors.New("invalid length: exceeds buffer size")
		}

		maxBufPos = bufPos + length
	} else {
		// Данные приходят без внешних тегов, парсим содержимое напрямую
		bufPos = 0
		maxBufPos = len(buffer)
	}

	response := &ReadResponse{}

	// Парсим поля confirmed-ResponsePDU
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
		case 0x02: // invokeID (INTEGER)
			response.InvokeID = ber.DecodeUint32(buffer, length, bufPos)
			bufPos += length

		case 0xA4: // confirmedServiceResponse: read (Context-specific 4, Constructed)
			// Парсим read response
			readResponse, err := parseReadServiceResponse(buffer[bufPos:bufPos+length], length)
			if err != nil {
				return nil, fmt.Errorf("failed to parse read service response: %w", err)
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

// parseReadResponseWithoutWrapper парсит read response без обертки confirmed-ResponsePDU
// Структура: a1 (read) + length + invokeID + confirmedServiceResponse
func parseReadResponseWithoutWrapper(buffer []byte) (*ReadResponse, error) {
	if len(buffer) < 1 {
		return nil, errors.New("empty buffer")
	}

	// Проверяем, что это read (tag 0xA1)
	if buffer[0] != 0xA1 {
		return nil, fmt.Errorf("invalid tag: expected 0xA1 (read), got 0x%02x", buffer[0])
	}

	response := &ReadResponse{}

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

	// Парсим поля read response
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
		case 0x02: // invokeID (INTEGER)
			response.InvokeID = ber.DecodeUint32(buffer, length, bufPos)
			bufPos += length

		case 0xA4: // confirmedServiceResponse: read (Context-specific 4, Constructed)
			// Парсим read response
			readResponse, err := parseReadServiceResponse(buffer[bufPos:bufPos+length], length)
			if err != nil {
				return nil, fmt.Errorf("failed to parse read service response: %w", err)
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
				Value:   value,
			})
			bufPos += length

		default:
			// Пропускаем неизвестные теги
			bufPos += length
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
				Value:   value,
			})
			bufPos += length

		case 0x80: // failure (Context-specific 0) - DataAccessError
			// Парсим ошибку
			errorCode := ber.DecodeUint32(buffer, length, bufPos)
			results = append(results, AccessResult{
				Success: false,
				Error: &DataAccessError{
					ErrorCode: errorCode,
				},
			})
			bufPos += length

		default:
			// Пропускаем неизвестные теги
			bufPos += length
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

// String возвращает строковое представление ReadResponse
func (r *ReadResponse) String() string {
	if len(r.ListOfAccessResult) == 0 {
		return fmt.Sprintf("ReadResponse{InvokeID: %d, Results: []}", r.InvokeID)
	}

	var results []string
	for i, result := range r.ListOfAccessResult {
		if result.Success {
			switch v := result.Value.(type) {
			case float32:
				results = append(results, fmt.Sprintf("Result[%d]: %f", i, v))
			case int32:
				results = append(results, fmt.Sprintf("Result[%d]: %d", i, v))
			case bool:
				results = append(results, fmt.Sprintf("Result[%d]: %t", i, v))
			case string:
				results = append(results, fmt.Sprintf("Result[%d]: %s", i, v))
			default:
				results = append(results, fmt.Sprintf("Result[%d]: %v", i, v))
			}
		} else {
			results = append(results, fmt.Sprintf("Result[%d]: Error(code=%d)", i, result.Error.ErrorCode))
		}
	}

	return fmt.Sprintf("ReadResponse{InvokeID: %d, Results: [%s]}", r.InvokeID, fmt.Sprint(results))
}

