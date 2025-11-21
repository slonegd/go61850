package acse

// BuildAARQ создаёт AARQ (Association Request) PDU.
// Возвращает захардкоженный AARQ согласно спецификации из poc/main.go.
func BuildAARQ(userData []byte) []byte {
	// AARQ согласно комментарию в poc/main.go:
	// 60 55
	// aarq
	// a1 07 06 05 28 ca 22 02 03 - aSO-context-name: 1.0.9506.2.3 (MMS)
	// a2 07 06 05 29 01 87 67 01 - called-AP-title: ap-title-form2: 1.1.1.999.1 (iso.1.1.999.1)
	// a3 03 02 01 0c - called-AE-qualifier: aso-qualifier-form2: 12
	// a6 06 06 04 29 01 87 67 - calling-AP-title: ap-title-form2: 1.1.1.999 (iso.1.1.999)
	// a7 03 02 01 0c - calling-AE-qualifier: aso-qualifier-form2: 12
	// be 2f 28 2d - user-information: 1 item: Association-data
	// 02 01 03 - indirect-reference: 3
	// a0 28 - encoding: single-ASN1-type (0)
	// <userData>

	aarq := []byte{}

	// AARQ tag (Application 0, Constructed) = 0x60
	aarq = append(aarq, 0x60)

	// Вычисляем длину содержимого
	// aSO-context-name: 9 байт (a1 07 06 05 28 ca 22 02 03)
	// called-AP-title: 9 байт (a2 07 06 05 29 01 87 67 01)
	// called-AE-qualifier: 5 байт (a3 03 02 01 0c)
	// calling-AP-title: 8 байт (a6 06 06 04 29 01 87 67)
	// calling-AE-qualifier: 5 байт (a7 03 02 01 0c)
	// user-information: 4 байта заголовок + 3 байта + 2 байта + длина userData
	fixedPartLength := 9 + 9 + 5 + 8 + 5 + 4 + 3 + 2 + len(userData)
	totalLength := fixedPartLength

	// Добавляем длину
	if totalLength < 0x80 {
		aarq = append(aarq, byte(totalLength))
	} else if totalLength <= 0xFF {
		aarq = append(aarq, 0x81, byte(totalLength))
	} else {
		aarq = append(aarq, 0x82, byte(totalLength>>8), byte(totalLength&0xFF))
	}

	// aSO-context-name (Context-specific 1, Constructed)
	aarq = append(aarq, 0xA1, 0x07, 0x06, 0x05, 0x28, 0xca, 0x22, 0x02, 0x03)

	// called-AP-title (Context-specific 2, Constructed)
	aarq = append(aarq, 0xA2, 0x07, 0x06, 0x05, 0x29, 0x01, 0x87, 0x67, 0x01)

	// called-AE-qualifier (Context-specific 3, INTEGER)
	aarq = append(aarq, 0xA3, 0x03, 0x02, 0x01, 0x0C)

	// calling-AP-title (Context-specific 6, Constructed)
	aarq = append(aarq, 0xA6, 0x06, 0x06, 0x04, 0x29, 0x01, 0x87, 0x67)

	// calling-AE-qualifier (Context-specific 7, INTEGER)
	aarq = append(aarq, 0xA7, 0x03, 0x02, 0x01, 0x0C)

	// user-information (Context-specific 30, Constructed)
	// Вычисляем длину user-information содержимого
	// Правильная структура: Association-data = 47 байт
	//   = tag+length (2) + indirect-reference (3) + encoding (42) = 47
	//   где encoding = tag+length (2) + userData (40) = 42
	//
	// В коде разбито:
	//   3 = indirect-reference (02 01 03)
	//   1 = Association-data tag (28)
	//   1 = Association-data length (2d)
	//   1 = encoding tag (a0)
	//   1 = encoding length (28)
	//   len(userData) = 40 байт (MMS PDU)
	// Правильнее было бы: 2 (Association-data tag+length) + 3 (indirect-reference) + 42 (encoding) = 47
	userInfoLength := 3 + 1 + 1 + 1 + 1 + len(userData)
	aarq = append(aarq, 0xBE) // Context-specific 30
	if userInfoLength < 0x80 {
		aarq = append(aarq, byte(userInfoLength))
	} else if userInfoLength <= 0xFF {
		aarq = append(aarq, 0x81, byte(userInfoLength))
	} else {
		aarq = append(aarq, 0x82, byte(userInfoLength>>8), byte(userInfoLength&0xFF))
	}

	// Association-data (Application 28, Constructed)
	// Вычисляем длину Association-data содержимого
	// Правильная структура: 45 байт
	//   = indirect-reference (3) + encoding (42) = 45
	//   где encoding = tag+length (2) + userData (40) = 42
	//
	// В коде разбито (для компенсации недостающих байтов):
	//   2 = часть indirect-reference (02 01) - не хватает еще 1 байта (03)
	//   1 = оставшийся байт indirect-reference (03)
	//   1 = encoding tag (a0)
	//   1 = encoding length (28)
	//   len(userData) = 40 байт (MMS PDU)
	// Правильнее было бы: 3 (indirect-reference: 02 01 03) + 2 (encoding: a0 28) + 40 (userData) = 45
	assocDataLength := 2 + 1 + 1 + 1 + len(userData)
	aarq = append(aarq, 0x28) // Application 28
	if assocDataLength < 0x80 {
		aarq = append(aarq, byte(assocDataLength))
	} else if assocDataLength <= 0xFF {
		aarq = append(aarq, 0x81, byte(assocDataLength))
	} else {
		aarq = append(aarq, 0x82, byte(assocDataLength>>8), byte(assocDataLength&0xFF))
	}

	// indirect-reference (INTEGER 3)
	aarq = append(aarq, 0x02, 0x01, 0x03)

	// encoding: single-ASN1-type (Context-specific 0, Constructed)
	aarq = append(aarq, 0xA0)
	if len(userData) < 0x80 {
		aarq = append(aarq, byte(len(userData)))
	} else if len(userData) <= 0xFF {
		aarq = append(aarq, 0x81, byte(len(userData)))
	} else {
		aarq = append(aarq, 0x82, byte(len(userData)>>8), byte(len(userData)&0xFF))
	}
	aarq = append(aarq, userData...)

	return aarq
}
