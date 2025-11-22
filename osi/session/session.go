package session

// SSelector представляет селектор сессии
type SSelector struct {
	Value []byte
}

// Session представляет состояние сессии ISO 8327-1
type Session struct {
	callingSessionSelector SSelector
	calledSessionSelector  SSelector
	sessionRequirement     uint16
	protocolOptions        uint8
}

// NewSession создаёт новую сессию с параметрами по умолчанию
// Согласно IsoSession_init из C библиотеки:
// - sessionRequirement = 0x0002 (duplex functional unit)
// - callingSessionSelector = [0, 1]
// - calledSessionSelector = [0, 1]
// - protocolOptions = 0
func NewSession() *Session {
	return &Session{
		sessionRequirement: 0x0002, // duplex functional unit
		callingSessionSelector: SSelector{
			Value: []byte{0, 1},
		},
		calledSessionSelector: SSelector{
			Value: []byte{0, 1},
		},
		protocolOptions: 0,
	}
}

// encodeConnectAcceptItem кодирует Connect Accept Item
// Согласно encodeConnectAcceptItem из C библиотеки (строки 259-272)
func encodeConnectAcceptItem(buf []byte, offset int, options uint8) int {
	buf[offset] = 5 // Connect Accept Item
	offset++
	buf[offset] = 6 // Parameter length: 6
	offset++
	buf[offset] = 0x13 // Protocol Options
	offset++
	buf[offset] = 1 // Length: 1
	offset++
	buf[offset] = options // Protocol options value
	offset++
	buf[offset] = 0x16 // Version Number
	offset++
	buf[offset] = 1 // Length: 1
	offset++
	buf[offset] = 2 // Version = 2
	offset++
	return offset
}

// encodeSessionRequirement кодирует Session Requirement
// Согласно encodeSessionRequirement из C библиотеки (строки 289-298)
func encodeSessionRequirement(session *Session, buf []byte, offset int) int {
	buf[offset] = 0x14 // Session Requirement
	offset++
	buf[offset] = 2 // Length: 2
	offset++
	buf[offset] = byte(session.sessionRequirement >> 8) // High byte
	offset++
	buf[offset] = byte(session.sessionRequirement & 0xff) // Low byte
	offset++
	return offset
}

// encodeCallingSessionSelector кодирует Calling Session Selector
// Согласно encodeCallingSessionSelector из C библиотеки (строки 300-311)
func encodeCallingSessionSelector(session *Session, buf []byte, offset int) int {
	buf[offset] = 0x33 // Calling Session Selector
	offset++
	buf[offset] = byte(len(session.callingSessionSelector.Value)) // Size
	offset++
	for i := 0; i < len(session.callingSessionSelector.Value); i++ {
		buf[offset] = session.callingSessionSelector.Value[i]
		offset++
	}
	return offset
}

// encodeCalledSessionSelector кодирует Called Session Selector
// Согласно encodeCalledSessionSelector из C библиотеки (строки 313-324)
func encodeCalledSessionSelector(session *Session, buf []byte, offset int) int {
	buf[offset] = 0x34 // Called Session Selector
	offset++
	buf[offset] = byte(len(session.calledSessionSelector.Value)) // Size
	offset++
	for i := 0; i < len(session.calledSessionSelector.Value); i++ {
		buf[offset] = session.calledSessionSelector.Value[i]
		offset++
	}
	return offset
}

// encodeSessionUserData кодирует Session User Data
// Согласно encodeSessionUserData из C библиотеки (строки 326-333)
func encodeSessionUserData(buf []byte, offset int, payloadLength int) int {
	buf[offset] = 0xc1 // Session user data
	offset++
	// В Session Protocol длина параметра кодируется в коротком формате
	// даже для значений >= 128 (в отличие от BER)
	if payloadLength <= 0xFF {
		buf[offset] = byte(payloadLength)
		offset++
	} else {
		// Для длин > 255 используем длинный формат
		buf[offset] = 0x82
		offset++
		buf[offset] = byte(payloadLength >> 8)
		offset++
		buf[offset] = byte(payloadLength & 0xff)
		offset++
	}
	return offset
}

// BuildConnectSPDU создаёт CONNECT SPDU (Session Protocol Data Unit).
// Реализация основана на IsoSession_createConnectSpdu из C библиотеки (строки 335-367).
// Использует значения по умолчанию, соответствующие IsoSession_init.
func BuildConnectSPDU(userData []byte) []byte {
	session := NewSession()
	return buildConnectSPDUWithSession(session, userData)
}

// buildConnectSPDUWithSession создаёт CONNECT SPDU с использованием указанной сессии
func buildConnectSPDUWithSession(session *Session, userData []byte) []byte {
	// Вычисляем размер буфера заранее
	// SPDU Type (1) + Length (1) + Connect Accept Item (8) + Session Requirement (4) +
	// Calling Session Selector (2 + len) + Called Session Selector (2 + len) +
	// Session User Data (1-3 + len)
	connectAcceptItemLen := 8
	sessionRequirementLen := 4
	callingSelectorLen := 2 + len(session.callingSessionSelector.Value)
	calledSelectorLen := 2 + len(session.calledSessionSelector.Value)
	userDataHeaderLen := 2 // Обычно 2 байта (0xc1 + длина)
	if len(userData) > 0xFF {
		userDataHeaderLen = 4 // Длинный формат для длины > 255
	}

	totalHeaderLen := 1 + 1 + connectAcceptItemLen + sessionRequirementLen +
		callingSelectorLen + calledSelectorLen + userDataHeaderLen

	buf := make([]byte, totalHeaderLen+len(userData))
	offset := 0

	// SPDU Type: CONNECT (CN) = 13
	buf[offset] = 13
	offset++
	lengthOffset := offset
	offset++ // Пропускаем байт для длины - заполним позже

	// Connect Accept Item
	offset = encodeConnectAcceptItem(buf, offset, session.protocolOptions)

	// Session Requirement
	offset = encodeSessionRequirement(session, buf, offset)

	// Calling Session Selector
	offset = encodeCallingSessionSelector(session, buf, offset)

	// Called Session Selector
	offset = encodeCalledSessionSelector(session, buf, offset)

	// Session User Data
	offset = encodeSessionUserData(buf, offset, len(userData))

	// Копируем userData
	copy(buf[offset:], userData)
	offset += len(userData)

	// Вычисляем и записываем длину SPDU
	// Длина = (offset - lengthOffset - 1) + len(userData)
	// Но userData уже включен в offset, поэтому:
	spduLength := offset - lengthOffset - 1
	buf[lengthOffset] = byte(spduLength)

	return buf[:offset]
}
