package presentation

// BuildCPType создаёт CP-type (Presentation Protocol Data Unit).
// Возвращает захардкоженный CP-type согласно спецификации из poc/main.go.
func BuildCPType(userData []byte) []byte {
	// CP-type согласно комментарию в poc/main.go:
	// 31 81 99
	// CP-type
	// a0 03
	// mode-selector: mode-value: normal-mode (1)
	// 80 01 01
	// normal-mode-parameters: до конца пакета
	// a2 81 91
	// calling-presentation-selector: 00000001
	// 81 04 00 00 00 01
	// called-presentation-selector: 00000001
	// 82 04 00 00 00 01
	// presentation-context-definition-list: 2 items
	// a4 23
	// Context-list item [0]
	// 30 0f
	// 02 01 01 - presentation-context-identifier: 1 (id-as-acse)
	// 06 04 52 01 00 01 - abstract-syntax-name: 2.2.1.0.1 (id-as-acse)
	// 30 04 06 02 51 01 - transfer-syntax-name-list: 1 item: Transfer-syntax-name: 2.1.1 (basic-encoding)
	// Context-list item [1]
	// 30 10
	// 02 01 03 - presentation-context-identifier: 3 (mms-abstract-syntax-version1(1))
	// 06 05 28 ca 22 02 01 - abstract-syntax-name: 1.0.9506.2.1 (mms-abstract-syntax-version1(1))
	// 30 04 06 02 51 01 - Transfer-syntax-name: 2.1.1 (basic-encoding)
	// user-data: fully-encoded-data (1)
	// 61 <length>
	// fully-encoded-data: 1 item
	// 30 <length>
	// PDV-list
	// 02 01 01 - presentation-context-identifier: 1 (id-as-acse)
	// a0 <length> - presentation-data-values: single-ASN1-type (0)
	// <userData>

	cpType := []byte{}

	// CP-type tag (Application 1, Constructed) = 0x31
	cpType = append(cpType, 0x31)

	// Вычисляем длину содержимого CP-type
	// Правильная структура:
	//   mode-selector: 5 байт (a0 03 + 80 01 01)
	//   normal-mode-parameters: 148 байт (a2 81 91 + 145 содержимое)
	//     содержимое: calling (6) + called (6) + context-list (37) + user-data (96) = 145
	// Итого: 5 + 148 = 153 байта
	// 
	// В коде разбито по частям для упрощения:
	//   9 = normal-mode-parameters заголовок (3) + user-data заголовок (2) + fully-encoded-data заголовок (2) + presentation-data-values заголовок (2) = 9
	//   5 = mode-selector
	//   6 = calling-presentation-selector
	//   6 = called-presentation-selector
	//   37 = presentation-context-definition-list
	//   3 = PDV-list (02 01 01)
	//   len(userData) = 87 байт (MMS PDU)
	fixedPartLength := 9 + 5 + 6 + 6 + 37 + 3 + len(userData)
	totalLength := fixedPartLength

	// Добавляем длину
	if totalLength < 0x80 {
		cpType = append(cpType, byte(totalLength))
	} else if totalLength <= 0xFF {
		cpType = append(cpType, 0x81, byte(totalLength))
	} else {
		cpType = append(cpType, 0x82, byte(totalLength>>8), byte(totalLength&0xFF))
	}

	// mode-selector (Context-specific 0, Constructed)
	cpType = append(cpType, 0xA0, 0x03)
	// mode-value: normal-mode (1) (Context-specific 0, INTEGER)
	cpType = append(cpType, 0x80, 0x01, 0x01)

	// normal-mode-parameters (Context-specific 2, Constructed)
	// Вычисляем длину normal-mode-parameters
	// Правильная структура содержимого:
	//   calling-presentation-selector: 6 байт
	//   called-presentation-selector: 6 байт
	//   presentation-context-definition-list: 37 байт
	//   user-data: 96 байт (2 заголовок + 94 содержимое)
	// Итого: 6 + 6 + 37 + 96 = 145 байт
	// 
	// В коде разбито:
	//   6 = calling-presentation-selector
	//   6 = called-presentation-selector
	//   6 = user-data заголовок (2) + fully-encoded-data заголовок (2) + presentation-data-values заголовок (2) = 6
	//   37 = presentation-context-definition-list
	//   3 = PDV-list (02 01 01)
	//   len(userData) = 87 байт (MMS PDU)
	normalModeParamsLength := 6 + 6 + 6 + 37 + 3 + len(userData)
	cpType = append(cpType, 0xA2)
	if normalModeParamsLength < 0x80 {
		cpType = append(cpType, byte(normalModeParamsLength))
	} else if normalModeParamsLength <= 0xFF {
		cpType = append(cpType, 0x81, byte(normalModeParamsLength))
	} else {
		cpType = append(cpType, 0x82, byte(normalModeParamsLength>>8), byte(normalModeParamsLength&0xFF))
	}

	// calling-presentation-selector (Context-specific 1, OCTET STRING)
	cpType = append(cpType, 0x81, 0x04, 0x00, 0x00, 0x00, 0x01)

	// called-presentation-selector (Context-specific 2, OCTET STRING)
	cpType = append(cpType, 0x82, 0x04, 0x00, 0x00, 0x00, 0x01)

	// presentation-context-definition-list (Context-specific 4, Constructed)
	// Захардкоженный список контекстов
	cpType = append(cpType, 0xA4, 0x23) // Tag + Length (35 байт)
	// Context-list item [0]
	cpType = append(cpType, 0x30, 0x0F)                         // SEQUENCE, 15 байт
	cpType = append(cpType, 0x02, 0x01, 0x01)                   // presentation-context-identifier: 1
	cpType = append(cpType, 0x06, 0x04, 0x52, 0x01, 0x00, 0x01) // abstract-syntax-name: id-as-acse
	cpType = append(cpType, 0x30, 0x04, 0x06, 0x02, 0x51, 0x01) // transfer-syntax-name-list
	// Context-list item [1]
	cpType = append(cpType, 0x30, 0x10)                               // SEQUENCE, 16 байт
	cpType = append(cpType, 0x02, 0x01, 0x03)                         // presentation-context-identifier: 3
	cpType = append(cpType, 0x06, 0x05, 0x28, 0xca, 0x22, 0x02, 0x01) // abstract-syntax-name: mms-abstract-syntax-version1
	cpType = append(cpType, 0x30, 0x04, 0x06, 0x02, 0x51, 0x01)       // transfer-syntax-name-list

	// user-data: fully-encoded-data (Application 1, Constructed)
	// Вычисляем длину user-data содержимого
	// Правильная структура: fully-encoded-data SEQUENCE = 94 байта
	//   = SEQUENCE tag+length (2) + PDV-list (3) + presentation-data-values (89) = 94
	//   где presentation-data-values = tag+length (2) + userData (87) = 89
	// 
	// В коде разбито:
	//   3 = PDV-list (02 01 01)
	//   1 = SEQUENCE tag (30)
	//   1 = SEQUENCE length (5c)
	//   1 = presentation-data-values tag (a0)
	//   1 = presentation-data-values length (57)
	//   len(userData) = 87 байт (MMS PDU)
	userDataLength := 3 + 1 + 1 + 1 + 1 + len(userData)
	cpType = append(cpType, 0x61)                       // Application 1
	if userDataLength < 0x80 {
		cpType = append(cpType, byte(userDataLength))
	} else if userDataLength <= 0xFF {
		cpType = append(cpType, 0x81, byte(userDataLength))
	} else {
		cpType = append(cpType, 0x82, byte(userDataLength>>8), byte(userDataLength&0xFF))
	}

	// fully-encoded-data: 1 item (SEQUENCE)
	// Вычисляем длину fully-encoded-data содержимого
	// Правильная структура: 92 байта
	//   = PDV-list (3) + presentation-data-values (89) = 92
	//   где presentation-data-values = tag+length (2) + userData (87) = 89
	// 
	// В коде разбито (для компенсации недостающих байтов):
	//   2 = часть PDV-list (02 01) - не хватает еще 1 байта (01)
	//   1 = оставшийся байт PDV-list (01)
	//   1 = presentation-data-values tag (a0)
	//   1 = presentation-data-values length (57)
	//   len(userData) = 87 байт (MMS PDU)
	// Правильнее было бы: 3 (PDV-list: 02 01 01) + 2 (presentation-data-values: a0 57) + 87 (userData) = 92
	pdvListLength := 2 + 1 + 1 + 1 + len(userData)
	cpType = append(cpType, 0x30)                  // SEQUENCE
	if pdvListLength < 0x80 {
		cpType = append(cpType, byte(pdvListLength))
	} else if pdvListLength <= 0xFF {
		cpType = append(cpType, 0x81, byte(pdvListLength))
	} else {
		cpType = append(cpType, 0x82, byte(pdvListLength>>8), byte(pdvListLength&0xFF))
	}

	// PDV-list: presentation-context-identifier: 1
	cpType = append(cpType, 0x02, 0x01, 0x01)

	// presentation-data-values: single-ASN1-type (Context-specific 0, Constructed)
	cpType = append(cpType, 0xA0)
	if len(userData) < 0x80 {
		cpType = append(cpType, byte(len(userData)))
	} else if len(userData) <= 0xFF {
		cpType = append(cpType, 0x81, byte(len(userData)))
	} else {
		cpType = append(cpType, 0x82, byte(len(userData)>>8), byte(len(userData)&0xFF))
	}
	cpType = append(cpType, userData...)

	return cpType
}
