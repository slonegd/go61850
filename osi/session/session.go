package session

import (
	"errors"
	"fmt"

	"github.com/slonegd/go61850/logger"
)

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

// SessionSPDUType представляет тип Session SPDU
type SessionSPDUType uint8

const (
	SessionSPDUTypeConnect    SessionSPDUType = 13 // CONNECT (CN)
	SessionSPDUTypeAccept     SessionSPDUType = 14 // ACCEPT (AC)
	SessionSPDUTypeRefuse     SessionSPDUType = 15 // REFUSE (RF)
	SessionSPDUTypeFinish     SessionSPDUType = 17 // FINISH (FN)
	SessionSPDUTypeDisconnect SessionSPDUType = 25 // DISCONNECT (DN)
	SessionSPDUTypeData       SessionSPDUType = 1  // DATA TRANSFER (DT)
)

// SessionSPDU представляет Session Protocol Data Unit (ISO 8327-1)
type SessionSPDU struct {
	Type   SessionSPDUType // Тип SPDU
	Length uint8           // Длина SPDU (без полей Type и Length)
	Data   []byte          // Данные следующего уровня (Presentation)
}

// ParseSessionSPDU парсит Session SPDU из байтового буфера
func ParseSessionSPDU(data []byte) (*SessionSPDU, error) {
	if len(data) < 2 {
		return nil, errors.New("Session SPDU too short: need at least 2 bytes")
	}

	spdu := &SessionSPDU{
		Type:   SessionSPDUType(data[0]),
		Length: data[1],
	}

	if int(spdu.Length) < 0 {
		return nil, fmt.Errorf("invalid Session SPDU length: %d", spdu.Length)
	}

	// Вычисляем общую длину SPDU: Type (1) + Length (1) + Length bytes
	spduTotalLength := 2 + int(spdu.Length)
	if len(data) < spduTotalLength {
		return nil, fmt.Errorf("Session SPDU incomplete: need %d bytes, got %d", spduTotalLength, len(data))
	}

	// Ищем Session User Data (параметр 0xC1)
	// Парсим параметры, чтобы найти User Data
	offset := 2 // Начинаем после Type и Length
	userDataStart := -1
	userDataLength := 0

	for offset < spduTotalLength {
		if offset >= len(data) {
			break
		}

		paramType := data[offset]
		offset++

		if offset >= len(data) {
			break
		}

		paramLength := int(data[offset])
		offset++

		// Если это Session User Data (0xC1)
		if paramType == 0xC1 {
			// В Session Protocol длина параметра кодируется в коротком формате
			// даже для значений >= 128 (в отличие от BER)
			// Если длина <= 255, используется короткий формат (1 байт)
			// Если длина > 255, используется длинный формат (0x82 + 2 байта)
			if paramLength == 0x82 && offset+2 <= len(data) {
				// Длинный формат: 0x82 означает длину в 2 байта
				userDataLength = int(data[offset])<<8 | int(data[offset+1])
				offset += 2
			} else {
				// Короткий формат: длина уже прочитана (даже если >= 128)
				userDataLength = paramLength
			}

			userDataStart = offset
			offset += userDataLength
			break
		} else {
			// Пропускаем параметр
			if offset+paramLength > len(data) {
				break
			}
			offset += paramLength
		}
	}

	// Если нашли User Data, извлекаем его
	if userDataStart >= 0 && userDataStart+userDataLength <= len(data) {
		spdu.Data = make([]byte, userDataLength)
		copy(spdu.Data, data[userDataStart:userDataStart+userDataLength])
	} else {
		// Если не нашли User Data, данные пустые
		spdu.Data = []byte{}
	}

	return spdu, nil
}

// String реализует интерфейс fmt.Stringer для SessionSPDU
func (s *SessionSPDU) String() string {
	typeStr := "Unknown"
	switch s.Type {
	case SessionSPDUTypeConnect:
		typeStr = "CONNECT"
	case SessionSPDUTypeAccept:
		typeStr = "ACCEPT"
	case SessionSPDUTypeRefuse:
		typeStr = "REFUSE"
	case SessionSPDUTypeFinish:
		typeStr = "FINISH"
	case SessionSPDUTypeDisconnect:
		typeStr = "DISCONNECT"
	case SessionSPDUTypeData:
		typeStr = "DATA"
	}

	return fmt.Sprintf("SessionSPDU{Type: %s (%d), Length: %d, DataLength: %d}",
		typeStr, uint8(s.Type), s.Length, len(s.Data))
}

// LogSessionSPDU логирует Session SPDU с использованием указанного логгера
// Используется для логирования сессии после парсинга
func LogSessionSPDU(spdu *SessionSPDU, l logger.Logger) {
	if spdu == nil || l == nil {
		return
	}
	l.Debug("  %s", spdu)
}
