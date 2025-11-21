package session

// BuildConnectSPDU создаёт CONNECT SPDU (Session Protocol Data Unit).
// Возвращает захардкоженный CONNECT SPDU согласно спецификации из poc/main.go.
func BuildConnectSPDU(userData []byte) []byte {
	// CONNECT SPDU согласно комментарию в poc/main.go:
	// SPDU Type: CONNECT (CN) SPDU (13) | Length: 178
	// 0d b2
	// Connect Accept Item
	// Parameter type: Connect Accept Item (5) | Parameter length: 6
	// Protocol Options: Parameter type: Protocol Options (19) | Parameter length: 1 | Flags: 0x00
	// Version Number: Parameter type: Version Number (22) | Parameter length: 1 | Flags: 0x02, Protocol Version 2
	// 05 06 13 01 00 16 01 02
	// Session Requirement
	// Parameter type: Session Requirement (20)
	// Parameter length: 2
	// Flags: 0x0002, Duplex functional unit
	// 14 02 00 02
	// Calling Session Selector
	// Parameter type: Calling Session Selector (51)
	// Parameter length: 2
	// Calling Session Selector: 0001
	// 33 02 00 01
	// Called Session Selector
	// Parameter type: Called Session Selector (52)
	// Parameter length: 2
	// Called Session Selector: 0001
	// 34 02 00 01
	// Session user data
	// Parameter type: Session user data (193)
	// Parameter length: <длина userData>
	// c1 <length> <userData>

	spdu := []byte{}

	// SPDU Type: CONNECT (CN) = 0x0D
	spdu = append(spdu, 0x0D)

	// Вычисляем общую длину SPDU
	// Connect Accept Item: 8 байт (05 06 13 01 00 16 01 02)
	// Session Requirement: 4 байта (14 02 00 02)
	// Calling Session Selector: 4 байта (33 02 00 01)
	// Called Session Selector: 4 байта (34 02 00 01)
	// Session user data: 2 байта заголовок + длина userData
	fixedPartLength := 8 + 4 + 4 + 4 + 2 + len(userData)
	totalLength := fixedPartLength

	// Добавляем длину Session SPDU
	// ПРИМЕЧАНИЕ: В Session Protocol длина кодируется в коротком формате для значений <= 255
	// Согласно дампу из Wireshark: 0d b2 (длина 178 в коротком формате, хотя 178 >= 128)
	// Это особенность Session Protocol - короткий формат используется до 255, а не до 127
	if totalLength <= 0xFF {
		spdu = append(spdu, byte(totalLength))
	} else {
		// Для длин > 255 используем длинный формат
		spdu = append(spdu, 0x82, byte(totalLength>>8), byte(totalLength&0xFF))
	}

	// Connect Accept Item
	spdu = append(spdu, 0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02)

	// Session Requirement
	spdu = append(spdu, 0x14, 0x02, 0x00, 0x02)

	// Calling Session Selector
	spdu = append(spdu, 0x33, 0x02, 0x00, 0x01)

	// Called Session Selector
	spdu = append(spdu, 0x34, 0x02, 0x00, 0x01)

	// Session user data
	// ПРИМЕЧАНИЕ: В Session Protocol длина параметра кодируется в коротком формате
	// даже для значений >= 128 (в отличие от BER, где используется длинный формат)
	// Согласно дампу из Wireshark: c1 9c (длина 156 в коротком формате)
	spdu = append(spdu, 0xC1) // Parameter type: Session user data (193)
	// Используем короткий формат для длины (как в дампе из Wireshark)
	if len(userData) <= 0xFF {
		spdu = append(spdu, byte(len(userData)))
	} else {
		// Для длин > 255 используем длинный формат
		spdu = append(spdu, 0x82, byte(len(userData)>>8), byte(len(userData)&0xFF))
	}
	spdu = append(spdu, userData...)

	return spdu
}

