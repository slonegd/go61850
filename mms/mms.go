package mms

// calculateLengthBER вычисляет длину для BER-кодирования.
// Для упрощения в этом PoC поддерживает только короткий формат длины (до 127 байт).
func calculateLengthBER(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	// Для длин >= 128 используем длинный формат
	if length <= 0xFF {
		return []byte{0x81, byte(length)}
	}
	if length <= 0xFFFF {
		return []byte{0x82, byte(length >> 8), byte(length & 0xFF)}
	}
	// Для очень больших длин (в PoC не используется)
	return []byte{0x83, byte(length >> 16), byte((length >> 8) & 0xFF), byte(length & 0xFF)}
}

// encodeInteger кодирует INTEGER в BER.
// Поддерживает значения от 0 до 65535.
func encodeInteger(value int) []byte {
	if value < 0 || value > 65535 {
		panic("Integer out of range (0 - 65535) in PoC")
	}

	var valueBytes []byte
	if value <= 0x7F {
		valueBytes = []byte{byte(value)}
	} else if value <= 0xFF {
		valueBytes = []byte{byte(value >> 8), byte(value & 0xFF)}
	} else { // value <= 0xFFFF
		highByte := byte(value >> 8)
		if highByte > 0x7F {
			valueBytes = []byte{0x00, highByte, byte(value & 0xFF)}
		} else {
			valueBytes = []byte{highByte, byte(value & 0xFF)}
		}
	}

	ber := []byte{0x02} // Tag INTEGER
	ber = append(ber, byte(len(valueBytes)))
	ber = append(ber, valueBytes...)
	return ber
}

// encodeOidValue кодирует *значение* OBJECT IDENTIFIER в BER (без тега OBJECT IDENTIFIER и длины).
// Это значение будет использоваться внутри контекстно-зависимых тегов.
func encodeOidValue(oid []int) []byte {
	// Для простоты в PoC закодируем жестко заданные *значения* OID, как в примере.
	// OID 1.0.9506.1.1 -> 0x05 0xf1 0x00
	// OID 1.0.9506.2.1 -> 0x03 0xee 1c 0x00 0x00 0x04 0x08 0x00 0x00 79 0xef 0x18
	if len(oid) == 5 && oid[0] == 1 && oid[1] == 0 && oid[2] == 9506 && oid[3] == 1 && oid[4] == 1 {
		return []byte{0x05, 0xf1, 0x00}
	} else if len(oid) == 5 && oid[0] == 1 && oid[1] == 0 && oid[2] == 9506 && oid[3] == 2 && oid[4] == 1 {
		return []byte{0x03, 0xee, 0x1c, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x79, 0xef, 0x18}
	} else {
		panic("Unsupported OID in PoC")
	}
}

// buildPresentationContextDefinition собирает Presentation Context Definition (внутри списка).
// Это: presentation-context-identifier (80) + abstract-syntax-name (81) + transfer-syntax-name (82)
func buildPresentationContextDefinition() []byte {
	def := []byte{}

	// presentation-context-identifier (Context-specific 0, INTEGER 1)
	int1 := encodeInteger(1)[2:]                        // Возвращает [0x02, 0x01, 0x01]
	def = append(def, 0x80)                             // Tag
	def = append(def, calculateLengthBER(len(int1))[0]) // Length (берём только байт длины от внутреннего элемента)
	def = append(def, int1...)                          // Value INTEGER (без тега 0x02 и длины)

	// abstract-syntax-name (Context-specific 1, OID 1.0.9506.1.1)
	oid1Value := encodeOidValue([]int{1, 0, 9506, 1, 1})     // Возвращает [0x05, 0xf1, 0x00]
	def = append(def, 0x81)                                  // Tag
	def = append(def, calculateLengthBER(len(oid1Value))[0]) // Length (берём только байт длины от внутреннего элемента)
	def = append(def, oid1Value...)                          // Value OID (только значение)

	// transfer-syntax-name (Context-specific 2, OID 1.0.9506.2.1)
	oid2Value := encodeOidValue([]int{1, 0, 9506, 2, 1})     // Возвращает [0x03, 0xee, ...]
	def = append(def, 0x82)                                  // Tag
	def = append(def, calculateLengthBER(len(oid2Value))[0]) // Length (берём только байт длины от внутреннего элемента)
	def = append(def, oid2Value...)                          // Value OID (только значение)

	return def
}

// buildPresentationContextDefinitionList собирает Presentation Context Definition List (A4).
// Содержит одно определение контекста.
func buildPresentationContextDefinitionList() []byte {
	def := buildPresentationContextDefinition()
	list := []byte{}
	list = append(list, 0xA4)                            // Tag Presentation Context Definition List (Application 4, Constructed)
	list = append(list, calculateLengthBER(len(def))...) // Length of the definition
	list = append(list, def...)                          // The definition itself
	return list
}

// BuildInitiateRequestPDU создаёт MMS InitiateRequestPDU.
// Возвращает BER-кодированный пакет.
func BuildInitiateRequestPDU() []byte {
	// 1. Тег InitiateRequestApdu (Application 8, Constructed)
	requestApdu := []byte{0xA8}

	// 2. Подготовим внутренности InitiateRequestApdu
	innerContent := []byte{}

	// 2a. localDetailCalling (Context-specific 0, INTEGER 65000)
	int65000 := encodeInteger(65000)[2:]                                      // Возвращает [0x02, 0x03, 0x00, 0xFD, 0xE8]
	innerContent = append(innerContent, 0x80)                                 // Tag
	innerContent = append(innerContent, calculateLengthBER(len(int65000))[0]) // Length
	innerContent = append(innerContent, int65000...)                          // Value

	// 2b. proposedMaxServOutstandingCalling (Context-specific 1, INTEGER 5)
	int5_a := encodeInteger(5)[2:]                                          // Возвращает [0x02, 0x01, 0x05]
	innerContent = append(innerContent, 0x81)                               // Tag
	innerContent = append(innerContent, calculateLengthBER(len(int5_a))[0]) // Length
	innerContent = append(innerContent, int5_a...)                          // Value

	// 2c. proposedMaxServOutstandingCalled (Context-specific 2, INTEGER 5)
	int5_b := encodeInteger(5)[2:]                                          // Возвращает [0x02, 0x01, 0x05]
	innerContent = append(innerContent, 0x82)                               // Tag
	innerContent = append(innerContent, calculateLengthBER(len(int5_b))[0]) // Length
	innerContent = append(innerContent, int5_b...)                          // Value

	// 2d. proposedDataStructureNestingLevel (Context-specific 3, INTEGER 10)
	// Согласно комментарию в poc/main.go: 83 01 0a - это proposedDataStructureNestingLevel: 10
	// Но в оригинальном main.go это initiate-request-detail с выбором 0a
	// Из дампа видно, что это просто 83 01 0a, что соответствует INTEGER 10
	int10 := encodeInteger(10)[2:]                                         // Возвращает [0x02, 0x01, 0x0A]
	innerContent = append(innerContent, 0x83)                              // Tag
	innerContent = append(innerContent, calculateLengthBER(len(int10))[0]) // Length
	innerContent = append(innerContent, int10...)                          // Value

	// 2e. mmsInitRequestDetail (Application 4, Constructed)
	mmsInitDetail := buildMMSInitRequestDetail()
	innerContent = append(innerContent, mmsInitDetail...) // Добавляем a4 16 ...

	// 3. Вычисляем общую длину внутреннего содержимого
	totalInnerLength := len(innerContent)

	// 4. Добавляем длину к основному тегу InitiateRequestApdu
	requestApdu = append(requestApdu, calculateLengthBER(totalInnerLength)...)

	// 5. Добавляем внутреннее содержимое
	requestApdu = append(requestApdu, innerContent...)

	return requestApdu
}

// buildMMSInitRequestDetail собирает mmsInitRequestDetail (A4).
func buildMMSInitRequestDetail() []byte {
	detail := []byte{}

	// proposedVersionNumber (Context-specific 0, INTEGER 1)
	int1 := encodeInteger(1)[2:]
	detail = append(detail, 0x80)
	detail = append(detail, calculateLengthBER(len(int1))[0])
	detail = append(detail, int1...)

	// proposedParameterCBB (Context-specific 1, BIT STRING)
	// Значение: 0xf100 (захардкожено)
	// BIT STRING: 0x03 (tag) + length + unused bits + value
	// В данном случае: 0x81 0x03 0x05 0xf1 0x00
	// где 0x05 - unused bits (5 бит неиспользуемых), 0xf1 0x00 - значение
	detail = append(detail, 0x81)
	detail = append(detail, 0x03) // Length
	detail = append(detail, 0x05) // Unused bits
	detail = append(detail, 0xf1, 0x00)

	// servicesSupportedCalling (Context-specific 2, BIT STRING)
	// Значение: 0xee1c00000408000079ef18 (захардкожено)
	// BIT STRING: 0x82 0x0c 0x03 + value
	// где 0x03 - unused bits (3 бита неиспользуемых)
	detail = append(detail, 0x82)
	detail = append(detail, 0x0c) // Length (12 байт)
	detail = append(detail, 0x03) // Unused bits
	detail = append(detail, 0xee, 0x1c, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x79, 0xef, 0x18)

	// Обёртка в Application 4 (mmsInitRequestDetail)
	result := []byte{0xA4}
	result = append(result, calculateLengthBER(len(detail))...)
	result = append(result, detail...)

	return result
}
