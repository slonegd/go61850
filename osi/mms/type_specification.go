package mms

import (
	"errors"
	"fmt"

	"github.com/slonegd/go61850/ber"
)

// TypeSpecification представляет спецификацию типа MMS
// Согласно ISO/IEC 9506-2, TypeSpecification может быть:
// - structure (с именованными компонентами)
// - array
// - boolean
// - bit-string
// - integer
// - unsigned
// - floating-point
// - octet-string
// - visible-string
// - mmsString
// - utc-time
// - binary-time
type TypeSpecification struct {
	// Type - тип спецификации
	Type TypeSpecType
	// Structure - для структуры: компоненты с именами
	Structure *StructureTypeSpec
	// BitStringSize - для bit-string: размер в битах
	BitStringSize int
	// IntegerSize - для integer: размер в битах
	IntegerSize int
	// UnsignedSize - для unsigned: размер в битах
	UnsignedSize int
	// FloatingPoint - для floating-point: параметры формата
	FloatingPoint *FloatingPointTypeSpec
	// OctetStringSize - для octet-string: размер в октетах
	OctetStringSize int
	// VisibleStringSize - для visible-string: максимальный размер
	VisibleStringSize int
	// Array - для массива: количество элементов и тип элемента
	Array *ArrayTypeSpec
}

// TypeSpecType представляет тип спецификации
type TypeSpecType int

const (
	TypeSpecStructure TypeSpecType = iota
	TypeSpecArray
	TypeSpecBoolean
	TypeSpecBitString
	TypeSpecInteger
	TypeSpecUnsigned
	TypeSpecFloatingPoint
	TypeSpecOctetString
	TypeSpecVisibleString
	TypeSpecMMSString
	TypeSpecUTCTime
	TypeSpecBinaryTime
)

// StructureTypeSpec представляет спецификацию структуры
type StructureTypeSpec struct {
	Components []ComponentSpec
}

// ComponentSpec представляет компонент структуры
type ComponentSpec struct {
	Name string
	Type *TypeSpecification
}

// ArrayTypeSpec представляет спецификацию массива
type ArrayTypeSpec struct {
	ElementCount int
	ElementType  *TypeSpecification
}

// FloatingPointTypeSpec представляет спецификацию floating-point
type FloatingPointTypeSpec struct {
	ExponentWidth int
	FormatWidth   int
}

// VariableAccessAttributesResponse представляет MMS GetVariableAccessAttributes Response PDU
// Структура согласно ISO/IEC 9506-2:
//
//	confirmed-ResponsePDU ::= SEQUENCE {
//	  invokeID            [0] IMPLICIT Unsigned32,
//	  confirmedServiceResponse [1] CHOICE {
//	    getVariableAccessAttributes [6] GetVariableAccessAttributes-Response
//	  }
//	}
//
//	GetVariableAccessAttributes-Response ::= SEQUENCE {
//	  mmsDeletable [0] IMPLICIT BOOLEAN,
//	  address [1] Address OPTIONAL,
//	  typeSpecification [2] TypeSpecification
//	}
//
// Пример ответа из wireshark (из комментария в go61850.go):
// a1 82 01 0b - confirmed-ResponsePDU (Context-specific 1, Constructed, длина 0x010b)
//
//	02 01 02 - invokeID (INTEGER, длина 1, значение 2)
//	a6 82 01 04 - confirmedServiceResponse: getVariableAccessAttributes (Context-specific 6, Constructed, длина 0x0104)
//	  80 01 00 - mmsDeletable: false (tag 0x80, boolean, длина 1, значение 0x00)
//	  a2 81 fe - typeSpecification: structure (tag 0xa2), длина 0x01fe
//	     a2 81 fb - structure components (tag 0xa2), длина 0x01fb
//	        a1 81 f8 - component item (tag 0xa1, SEQUENCE), длина 0x01f8
//	           30 3c - SEQUENCE (tag 0x30), длина 0x3c
//	              80 05 - componentName (tag 0x80, VisibleString), длина 5
//	                 41 6e 49 6e 31 - "AnIn1"
//	               a1 33 - componentType: structure (tag 0xa1), длина 0x33
type VariableAccessAttributesResponse struct {
	InvokeID          uint32
	MmsDeletable      bool
	TypeSpecification *TypeSpecification
}

// ParseGetVariableAccessAttributesResponse парсит ответ getVariableAccessAttributes из байтов
// Структура согласно ISO/IEC 9506-2:
//
//	GetVariableAccessAttributesResponse ::= SEQUENCE {
//	  mmsDeletable [0] IMPLICIT BOOLEAN,
//	  typeSpecification [1] TypeSpecification
//	}
//
//	TypeSpecification ::= CHOICE {
//	  structure [2] IMPLICIT SEQUENCE OF SEQUENCE {
//	    componentName VisibleString,
//	    componentType TypeSpecification
//	  },
//	  array [3] IMPLICIT SEQUENCE {
//	    numberOfElements Unsigned32,
//	    elementType TypeSpecification
//	  },
//	  boolean [4] IMPLICIT NULL,
//	  bit-string [5] IMPLICIT Unsigned32,
//	  integer [6] IMPLICIT Unsigned32,
//	  unsigned [7] IMPLICIT Unsigned32,
//	  floating-point [8] IMPLICIT SEQUENCE {
//	    exponentwidth Unsigned8,
//	    formatwidth Unsigned8
//	  },
//	  octet-string [9] IMPLICIT Unsigned32,
//	  visible-string [10] IMPLICIT Unsigned32,
//	  mmsString [11] IMPLICIT Unsigned32,
//	  utc-time [12] IMPLICIT NULL,
//	  binary-time [13] IMPLICIT Unsigned8
//	}
//
// Пример ответа из wireshark (из комментария в go61850.go):
// a6 82 01 04 - getVariableAccessAttributes response (tag 0xa6), длина 0x0104
//
//	80 01 00 - mmsDeletable: false (tag 0x80, boolean)
//	a2 81 fe - typeSpecification: structure (tag 0xa2), длина 0x01fe
//	   a2 81 fb - structure components (tag 0xa2), длина 0x01fb
//	      a1 81 f8 - component item (tag 0xa1, SEQUENCE), длина 0x01f8
//	         30 3c - SEQUENCE (tag 0x30), длина 0x3c
//	            80 05 - componentName (tag 0x80, VisibleString), длина 5
//	               41 6e 49 6e 31 - "AnIn1"
//	            a1 33 - componentType: structure (tag 0xa1), длина 0x33
//
// ParseGetVariableAccessAttributesResponse парсит MMS GetVariableAccessAttributes Response PDU из BER-кодированного буфера
// Структура из wireshark (из комментария в go61850.go):
// a1 82 01 0b - confirmed-ResponsePDU (Context-specific 1, Constructed, длина 0x010b)
//
//	02 01 02 - invokeID (INTEGER, длина 1, значение 2)
//	a6 82 01 04 - confirmedServiceResponse: getVariableAccessAttributes (Context-specific 6, Constructed, длина 0x0104)
//	  80 01 00 - mmsDeletable: false (tag 0x80, boolean, длина 1, значение 0x00)
//	  a2 81 fe - typeSpecification: structure (tag 0xa2), длина 0x01fe
//
// После установления соединения данные могут приходить без внешнего тега confirmed-ResponsePDU
func ParseGetVariableAccessAttributesResponse(buffer []byte) (*VariableAccessAttributesResponse, error) {
	var response VariableAccessAttributesResponse
	if len(buffer) == 0 {
		return nil, errors.New("empty buffer")
	}

	// Проверяем формат данных
	// После установления соединения данные могут приходить в разных форматах:
	// 1. Стандартный: a0 (confirmed-ResponsePDU) + length + invokeID + confirmedServiceResponse
	// 2. С тегом a1: a1 (confirmed-ResponsePDU) + length + invokeID + confirmedServiceResponse
	// 3. Прямое содержимое: invokeID + confirmedServiceResponse (без внешних тегов)
	var bufPos int
	var maxBufPos int

	if buffer[0] == 0xA0 || buffer[0] == 0xA1 {
		// Стандартный формат с тегом confirmed-ResponsePDU
		bufPos = 1
		maxBufPos = len(buffer)

		// Декодируем длину
		newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			return nil, fmt.Errorf("failed to decode confirmed-ResponsePDU length: %w", err)
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

		case 0xA6: // confirmedServiceResponse: getVariableAccessAttributes (Context-specific 6, Constructed)
			// Парсим getVariableAccessAttributes response
			mmsDeletable, typeSpec, err := parseGetVariableAccessAttributesResponseContent(buffer[bufPos:bufPos+length], length)
			if err != nil {
				return nil, fmt.Errorf("failed to parse getVariableAccessAttributes response: %w", err)
			}
			response.MmsDeletable = mmsDeletable
			response.TypeSpecification = typeSpec
			return &response, nil

		default:
			// Пропускаем неизвестные теги
			bufPos += length
		}
	}

	return nil, errors.New("getVariableAccessAttributes response not found")
}

// parseGetVariableAccessAttributesResponseContent парсит содержимое getVariableAccessAttributes response
// Возвращает mmsDeletable и typeSpecification
func parseGetVariableAccessAttributesResponseContent(buffer []byte, maxLength int) (bool, *TypeSpecification, error) {
	bufPos := 0
	maxBufPos := len(buffer)
	if maxLength < maxBufPos {
		maxBufPos = maxLength
	}

	var mmsDeletable bool
	var typeSpec *TypeSpecification

	// Пропускаем возможные SEQUENCE теги (0x30)
	for bufPos < maxBufPos && buffer[bufPos] == 0x30 {
		bufPos++
		newPos, seqLength, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			break
		}
		bufPos = newPos
		if bufPos+seqLength > maxBufPos {
			break
		}
		// Продолжаем парсинг внутри SEQUENCE
	}

	// Парсим mmsDeletable (tag 0x80) и typeSpecification
	for bufPos < maxBufPos {
		tagStart := bufPos
		tag := buffer[bufPos]
		bufPos++

		newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			return false, nil, fmt.Errorf("failed to decode length for tag 0x%02x: %w", tag, err)
		}
		bufPos = newPos

		if bufPos+length > maxBufPos {
			return false, nil, fmt.Errorf("invalid length for tag 0x%02x: exceeds buffer size", tag)
		}

		switch tag {
		case 0x80: // mmsDeletable (boolean)
			// Парсим boolean значение
			// BOOLEAN кодируется как один байт: 0x00 = false, 0xFF = true
			if length > 0 {
				mmsDeletable = buffer[bufPos] != 0x00
			}
			bufPos += length

		case 0xA1: // address (опционально, Context-specific 1, Constructed)
			// Пропускаем address, так как оно опционально и не используется в текущей реализации
			bufPos += length

		case 0xA2: // typeSpecification: structure (tag 0xa2)
			// Парсим TypeSpecification
			// tagStart указывает на начало тега, bufPos - на начало содержимого после декодирования длины
			// typeSpecification заканчивается на bufPos + length
			// Включаем весь typeSpecification от начала тега до конца содержимого
			typeSpecEnd := bufPos + length
			if typeSpecEnd > len(buffer) {
				typeSpecEnd = len(buffer)
			}
			typeSpecBuf := buffer[tagStart:typeSpecEnd]
			var err error
			typeSpec, err = parseTypeSpecification(typeSpecBuf, len(typeSpecBuf))
			if err != nil {
				return false, nil, fmt.Errorf("failed to parse typeSpecification: %w", err)
			}
			// После парсинга typeSpecification можно вернуть результат
			if typeSpec != nil {
				return mmsDeletable, typeSpec, nil
			}

		default:
			// Проверяем, может быть это typeSpecification с другим тегом
			// Попробуем распарсить как typeSpecification
			typeSpecEnd := bufPos + length
			if typeSpecEnd > len(buffer) {
				typeSpecEnd = len(buffer)
			}
			typeSpecBuf := buffer[tagStart:typeSpecEnd]
			var err error
			typeSpec, err = parseTypeSpecification(typeSpecBuf, len(typeSpecBuf))
			if err == nil && typeSpec != nil {
				return mmsDeletable, typeSpec, nil
			}
			// Если не получилось, пропускаем неизвестный тег
			bufPos += length
		}
	}

	if typeSpec == nil {
		return false, nil, errors.New("typeSpecification not found in getVariableAccessAttributes response")
	}

	return mmsDeletable, typeSpec, nil
}

// parseTypeSpecification парсит TypeSpecification из байтов
func parseTypeSpecification(buffer []byte, maxLength int) (*TypeSpecification, error) {
	if len(buffer) == 0 {
		return nil, errors.New("empty buffer for TypeSpecification")
	}

	bufPos := 0
	maxBufPos := len(buffer)
	if maxLength < maxBufPos {
		maxBufPos = maxLength
	}

	// Проверяем первый тег для определения типа
	// TypeSpecification может начинаться с разных тегов в зависимости от типа
	// structure: тег 0xa2 (или 0xa1 для вложенной структуры)
	// array: тег 0xa3
	// boolean: тег 0x84
	// bit-string: тег 0x85
	// integer: тег 0x86
	// unsigned: тег 0x87
	// floating-point: тег 0x88
	// octet-string: тег 0x89
	// visible-string: тег 0x8a
	// mmsString: тег 0x8b
	// utc-time: тег 0x8c
	// binary-time: тег 0x8d

	// Проверяем, является ли это структурой (тег 0xa2 или 0xa1)
	if buffer[0] == 0xA2 || buffer[0] == 0xA1 {
		return parseStructureTypeSpec(buffer, maxLength)
	}

	// Для других типов парсим по первому байту
	tag := buffer[0]
	bufPos = 1

	newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TypeSpecification length: %w", err)
	}
	bufPos = newPos

	if bufPos+length > maxBufPos {
		return nil, fmt.Errorf("invalid TypeSpecification length: exceeds buffer size")
	}

	switch tag {
	case 0xA3: // array
		return parseArrayTypeSpec(buffer[bufPos:bufPos+length], length)

	case 0x84: // boolean
		return &TypeSpecification{Type: TypeSpecBoolean}, nil

	case 0x85: // bit-string
		bitSize := int(ber.DecodeUint32(buffer, length, bufPos))
		return &TypeSpecification{
			Type:          TypeSpecBitString,
			BitStringSize: bitSize,
		}, nil

	case 0x86: // integer
		intSize := int(ber.DecodeUint32(buffer, length, bufPos))
		return &TypeSpecification{
			Type:        TypeSpecInteger,
			IntegerSize: intSize,
		}, nil

	case 0x87: // unsigned
		unsignedSize := int(ber.DecodeUint32(buffer, length, bufPos))
		return &TypeSpecification{
			Type:         TypeSpecUnsigned,
			UnsignedSize: unsignedSize,
		}, nil

	case 0x88: // floating-point
		return parseFloatingPointTypeSpec(buffer[bufPos:bufPos+length], length)

	case 0x89: // octet-string
		octetSize := int(ber.DecodeUint32(buffer, length, bufPos))
		return &TypeSpecification{
			Type:            TypeSpecOctetString,
			OctetStringSize: octetSize,
		}, nil

	case 0x8A: // visible-string
		visibleSize := int(ber.DecodeUint32(buffer, length, bufPos))
		return &TypeSpecification{
			Type:              TypeSpecVisibleString,
			VisibleStringSize: visibleSize,
		}, nil

	case 0x8B: // mmsString
		return &TypeSpecification{Type: TypeSpecMMSString}, nil

	case 0x8C: // utc-time
		return &TypeSpecification{Type: TypeSpecUTCTime}, nil

	case 0x8D: // binary-time
		_ = int(buffer[bufPos]) // binary-time size (4 or 6), but we don't need it for now
		return &TypeSpecification{Type: TypeSpecBinaryTime}, nil

	default:
		return nil, fmt.Errorf("unsupported TypeSpecification tag: 0x%02x", tag)
	}
}

// parseStructureTypeSpec парсит спецификацию структуры
// Структура согласно ISO/IEC 9506-2:
//
//	structure [2] IMPLICIT SEQUENCE OF SEQUENCE {
//	  componentName VisibleString,
//	  componentType TypeSpecification
//	}
func parseStructureTypeSpec(buffer []byte, maxLength int) (*TypeSpecification, error) {
	bufPos := 0
	maxBufPos := len(buffer)
	if maxLength < maxBufPos {
		maxBufPos = maxLength
	}

	// Пропускаем внешний тег structure (0xa2 или 0xa1)
	if buffer[0] == 0xA2 || buffer[0] == 0xA1 {
		bufPos = 1
		newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			return nil, fmt.Errorf("failed to decode structure length: %w", err)
		}
		bufPos = newPos
		maxBufPos = bufPos + length
		if maxBufPos > len(buffer) {
			maxBufPos = len(buffer)
		}
	}

	var components []ComponentSpec

	// Парсим SEQUENCE OF компонентов
	// Компоненты могут быть закодированы как SEQUENCE OF с тегом 0xa2 или 0xa1,
	// или напрямую как последовательность SEQUENCE (tag 0x30)
	for bufPos < maxBufPos {
		// Проверяем, есть ли обёртка для компонентов
		componentStart := bufPos
		tag := buffer[bufPos]
		bufPos++

		newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			return nil, fmt.Errorf("failed to decode component sequence length: %w", err)
		}
		bufPos = newPos

		if bufPos+length > maxBufPos {
			return nil, fmt.Errorf("invalid component sequence length: exceeds buffer size")
		}

		// Если это тег структуры компонентов (0xa2 или 0xa1), пропускаем его и парсим содержимое
		if tag == 0xA2 || tag == 0xA1 {
			// Рекурсивно парсим структуру компонентов
			subBufPos := bufPos
			subMaxBufPos := bufPos + length

			// Парсим все компоненты внутри обёртки
			// Компоненты могут быть вложены в обёртку a1 или идти последовательно
			for subBufPos < subMaxBufPos {
				// Проверяем, есть ли еще компоненты для парсинга
				if subBufPos >= subMaxBufPos {
					break
				}

				// Проверяем, какой тег у следующего элемента
				nextTag := buffer[subBufPos]

				// Если это обёртка компонента (a1), парсим её содержимое
				if nextTag == 0xA1 {
					// Пропускаем тег и декодируем длину
					tempPos := subBufPos + 1
					newPos, innerLength, err := ber.DecodeLength(buffer, tempPos, subMaxBufPos)
					if err != nil {
						break
					}
					tempPos = newPos
					innerEnd := tempPos + innerLength

					// Парсим компоненты внутри обёртки a1
					// Внутри обёртки a1 идут компоненты с тегом 0x30 (SEQUENCE)
					innerBufPos := tempPos
					for innerBufPos < innerEnd {
						if innerBufPos >= innerEnd {
							break
						}
						innerTag := buffer[innerBufPos]
						if innerTag == 0x30 {
							// Это SEQUENCE компонента
							component, newInnerPos, err := parseComponent(buffer, innerBufPos, innerEnd)
							if err != nil {
								// Если ошибка парсинга компонента, пропускаем его и продолжаем
								// Пытаемся найти следующий компонент, пропуская текущий
								// Вычисляем примерный размер компонента по длине SEQUENCE
								tempPos := innerBufPos + 1
								if tempPos < innerEnd {
									newTempPos, seqLength, err := ber.DecodeLength(buffer, tempPos, innerEnd)
									if err == nil {
										innerBufPos = newTempPos + seqLength
										continue
									}
								}
								// Если не удалось пропустить, выходим
								break
							}
							if component != nil {
								components = append(components, *component)
							}
							// Проверяем, что позиция изменилась и не вышла за границы
							if newInnerPos <= innerBufPos {
								break
							}
							if newInnerPos >= innerEnd {
								// Достигли конца обёртки
								break
							}
							innerBufPos = newInnerPos
						} else {
							// Не SEQUENCE, возможно конец компонентов
							break
						}
					}
					// Переходим к следующему элементу после обёртки a1
					// Нужно пропустить тег a1, байты длины и содержимое
					// Вычисляем полный размер обёртки: 1 (тег) + длина байтов + innerLength
					lengthBytesSize := newPos - (subBufPos + 1)
					subBufPos = subBufPos + 1 + lengthBytesSize + innerLength
				} else if nextTag == 0x30 {
					// Это SEQUENCE компонента, парсим его напрямую
					component, newSubBufPos, err := parseComponent(buffer, subBufPos, subMaxBufPos)
					if err != nil {
						break
					}
					if component != nil {
						components = append(components, *component)
					}
					if newSubBufPos <= subBufPos || newSubBufPos >= subMaxBufPos {
						break
					}
					subBufPos = newSubBufPos
				} else {
					// Неизвестный тег, возможно конец
					break
				}
			}
			bufPos += length
		} else if tag == 0x30 {
			// Это SEQUENCE компонента, парсим его
			component, newBufPos, err := parseComponent(buffer, componentStart, maxBufPos)
			if err != nil {
				return nil, fmt.Errorf("failed to parse component: %w", err)
			}
			if component != nil {
				components = append(components, *component)
			}
			bufPos = newBufPos
		} else {
			return nil, fmt.Errorf("unexpected tag in structure components: 0x%02x", tag)
		}
	}

	return &TypeSpecification{
		Type: TypeSpecStructure,
		Structure: &StructureTypeSpec{
			Components: components,
		},
	}, nil
}

// parseComponent парсит один компонент структуры (SEQUENCE с componentName и componentType)
// Возвращает компонент и новую позицию в буфере
func parseComponent(buffer []byte, bufPos, maxBufPos int) (*ComponentSpec, int, error) {
	if bufPos >= maxBufPos {
		return nil, bufPos, nil
	}

	componentStart := bufPos
	tag := buffer[bufPos]
	bufPos++

	// Пропускаем тег SEQUENCE или component item (0xa1)
	// Сохраняем componentStart для возможного использования
	_ = componentStart
	if tag != 0x30 && tag != 0xA1 {
		return nil, bufPos, fmt.Errorf("expected SEQUENCE or component item tag, got 0x%02x", tag)
	}

	newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
	if err != nil {
		return nil, bufPos, fmt.Errorf("failed to decode component length: %w", err)
	}
	bufPos = newPos

	if bufPos+length > maxBufPos {
		return nil, bufPos, fmt.Errorf("invalid component length: exceeds buffer size")
	}

	componentEnd := bufPos + length
	if componentEnd > maxBufPos {
		componentEnd = maxBufPos
	}
	var component ComponentSpec

	// Парсим componentName (tag 0x80, VisibleString)
	// и componentType (tag 0xa1 или другие для TypeSpecification)
	for bufPos < componentEnd {
		tagStart := bufPos // Сохраняем позицию начала тега
		tag := buffer[bufPos]
		bufPos++

		if bufPos >= componentEnd {
			break
		}

		newPos, fieldLength, err := ber.DecodeLength(buffer, bufPos, componentEnd)
		if err != nil {
			return nil, bufPos, fmt.Errorf("failed to decode field length in component: %w", err)
		}
		bufPos = newPos

		if bufPos+fieldLength > componentEnd {
			return nil, bufPos, fmt.Errorf("invalid field length in component: exceeds buffer size")
		}

		switch tag {
		case 0x80: // componentName (VisibleString)
			// Декодируем VisibleString
			if bufPos+fieldLength > len(buffer) {
				return nil, bufPos, fmt.Errorf("componentName exceeds buffer")
			}
			component.Name = string(buffer[bufPos : bufPos+fieldLength])
			bufPos += fieldLength

		case 0xA1, 0xA2: // componentType (TypeSpecification - structure)
			// Парсим TypeSpecification начиная с тега
			// Для структуры нужно передать только TypeSpecification, а не весь оставшийся буфер
			// Вычисляем размер TypeSpecification: тег + длина + содержимое
			typeSpecEnd := bufPos + fieldLength
			if tagStart >= len(buffer) || typeSpecEnd > len(buffer) {
				// Если ошибка границ буфера, пропускаем это поле и продолжаем
				bufPos += fieldLength
				continue
			}
			typeSpecBuf := buffer[tagStart:typeSpecEnd]
			typeSpec, err := parseTypeSpecification(typeSpecBuf, len(typeSpecBuf))
			if err != nil {
				// Если ошибка парсинга, пропускаем тип и продолжаем без заполнения типа
				// Это позволяет продолжить парсинг остальных компонентов
				bufPos += fieldLength
				continue
			}
			component.Type = typeSpec
			// Обновляем bufPos на конец TypeSpecification (не componentEnd, чтобы не пропустить другие поля)
			bufPos = typeSpecEnd

		default:
			// Парсим как TypeSpecification других типов (boolean, bit-string, integer, etc.)
			// Для простых типов нужно передать только тег и его содержимое
			if tagStart >= len(buffer) || bufPos+fieldLength > len(buffer) {
				bufPos += fieldLength
				continue
			}
			// Создаем буфер только для этого TypeSpecification: тег + длина + содержимое
			typeSpecBuf := buffer[tagStart : bufPos+fieldLength]
			typeSpec, err := parseTypeSpecification(typeSpecBuf, len(typeSpecBuf))
			if err == nil && typeSpec != nil {
				component.Type = typeSpec
			}
			// Всегда обновляем позицию на конец этого поля
			bufPos += fieldLength
		}
	}

	return &component, componentEnd, nil
}

// parseArrayTypeSpec парсит спецификацию массива
func parseArrayTypeSpec(buffer []byte, maxLength int) (*TypeSpecification, error) {
	bufPos := 0
	maxBufPos := len(buffer)
	if maxLength < maxBufPos {
		maxBufPos = maxLength
	}

	var elementCount int
	var elementType *TypeSpecification

	for bufPos < maxBufPos {
		tagStart := bufPos // Сохраняем позицию начала тега
		tag := buffer[bufPos]
		bufPos++

		if bufPos >= maxBufPos {
			break
		}

		newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			return nil, fmt.Errorf("failed to decode array field length: %w", err)
		}
		bufPos = newPos

		if bufPos+length > maxBufPos {
			return nil, fmt.Errorf("invalid array field length: exceeds buffer size")
		}

		switch tag {
		case 0x02: // numberOfElements (INTEGER)
			elementCount = int(ber.DecodeUint32(buffer, length, bufPos))
			bufPos += length

		case 0xA1, 0xA2: // elementType (TypeSpecification)
			// Парсим TypeSpecification начиная с тега
			if tagStart >= len(buffer) || maxBufPos > len(buffer) {
				return nil, fmt.Errorf("invalid buffer bounds for array elementType")
			}
			var err error
			elementType, err = parseTypeSpecification(buffer[tagStart:maxBufPos], maxBufPos-tagStart)
			if err != nil {
				return nil, fmt.Errorf("failed to parse array elementType: %w", err)
			}
			bufPos = maxBufPos

		default:
			bufPos += length
		}
	}

	if elementType == nil {
		return nil, errors.New("array elementType not found")
	}

	return &TypeSpecification{
		Type: TypeSpecArray,
		Array: &ArrayTypeSpec{
			ElementCount: elementCount,
			ElementType:  elementType,
		},
	}, nil
}

// parseFloatingPointTypeSpec парсит спецификацию floating-point
func parseFloatingPointTypeSpec(buffer []byte, maxLength int) (*TypeSpecification, error) {
	bufPos := 0
	maxBufPos := len(buffer)
	if maxLength < maxBufPos {
		maxBufPos = maxLength
	}

	var exponentWidth, formatWidth int

	for bufPos < maxBufPos {
		tag := buffer[bufPos]
		bufPos++

		newPos, length, err := ber.DecodeLength(buffer, bufPos, maxBufPos)
		if err != nil {
			return nil, fmt.Errorf("failed to decode floating-point field length: %w", err)
		}
		bufPos = newPos

		if bufPos+length > maxBufPos {
			return nil, fmt.Errorf("invalid floating-point field length: exceeds buffer size")
		}

		switch tag {
		case 0x02: // exponentwidth или formatwidth (INTEGER)
			value := int(ber.DecodeUint32(buffer, length, bufPos))
			if exponentWidth == 0 {
				exponentWidth = value
			} else {
				formatWidth = value
			}
			bufPos += length

		default:
			bufPos += length
		}
	}

	return &TypeSpecification{
		Type: TypeSpecFloatingPoint,
		FloatingPoint: &FloatingPointTypeSpec{
			ExponentWidth: exponentWidth,
			FormatWidth:   formatWidth,
		},
	}, nil
}
