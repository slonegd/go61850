package session

import (
	"testing"
)

// Тест парсинга ACCEPT SPDU из комментария в go61850.go (строки 143-144)
// Пакет без уровней TPKT и COTP
func TestParseSessionSPDU_AcceptFromComment(t *testing.T) {
	// Полный пакет из комментария (строка 143):
	// 03 00 00 8f 02 f0 80 0e 86 05 06 13 01 00 16 01 02 14 02 00 02 34 02 00 01 c1 74 31 72 a0 03 80 01 01 a2 6b 83 04 00 00 00 01 a5 12 30 07 80 01 00 81 02 51 01 30 07 80 01 00 81 02 51 01 61 4f 30 4d 02 01 01 a0 48 61 46 a1 07 06 05 28 ca 22 02 03 a2 03 02 01 00 a3 05 a1 03 02 01 00 be 2f 28 2d 02 01 03 a0 28 a9 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 00 02 00 00 40 ed 18
	//
	// TPKT: 03 00 00 8f (4 байта)
	// COTP: 02 f0 80 (3 байта)
	// Session SPDU начинается с байта 7 (0e 86 ...)

	fullPacket := []byte{
		0x03, 0x00, 0x00, 0x8f, // TPKT
		0x02, 0xf0, 0x80, // COTP
		// Session SPDU начинается здесь:
		0x0e,       // SPDU Type: ACCEPT (14)
		0x86,       // Length: 134
		0x05, 0x06, // Connect Accept Item, length: 6
		0x13, 0x01, 0x00, // Protocol Options (19), length: 1, value: 0x00
		0x16, 0x01, 0x02, // Version Number (22), length: 1, value: 0x02
		0x14, 0x02, 0x00, 0x02, // Session Requirement (20), length: 2, value: 0x0002
		0x34, 0x02, 0x00, 0x01, // Called Session Selector (52), length: 2, value: 0x0001
		0xc1, 0x74, // Session user data (193), length: 116 (0x74)
		// Presentation data (116 байт):
		0x31, 0x72, 0xa0, 0x03, 0x80, 0x01, 0x01, 0xa2, 0x6b, 0x83, 0x04, 0x00, 0x00, 0x00, 0x01, 0xa5,
		0x12, 0x30, 0x07, 0x80, 0x01, 0x00, 0x81, 0x02, 0x51, 0x01, 0x30, 0x07, 0x80, 0x01, 0x00, 0x81,
		0x02, 0x51, 0x01, 0x61, 0x4f, 0x30, 0x4d, 0x02, 0x01, 0x01, 0xa0, 0x48, 0x61, 0x46, 0xa1, 0x07,
		0x06, 0x05, 0x28, 0xca, 0x22, 0x02, 0x03, 0xa2, 0x03, 0x02, 0x01, 0x00, 0xa3, 0x05, 0xa1, 0x03,
		0x02, 0x01, 0x00, 0xbe, 0x2f, 0x28, 0x2d, 0x02, 0x01, 0x03, 0xa0, 0x28, 0xa9, 0x26, 0x80, 0x03,
		0x00, 0xfd, 0xe8, 0x81, 0x01, 0x05, 0x82, 0x01, 0x05, 0x83, 0x01, 0x0a, 0xa4, 0x16, 0x80, 0x01,
		0x01, 0x81, 0x03, 0x05, 0xf1, 0x00, 0x82, 0x0c, 0x03, 0xee, 0x1c, 0x00, 0x00, 0x00, 0x02, 0x00,
		0x00, 0x40, 0xed, 0x18,
	}

	// Убираем TPKT и COTP, оставляем только Session SPDU
	sessionData := fullPacket[7:] // Пропускаем первые 7 байт (TPKT + COTP)

	// Парсим Session SPDU
	spdu, err := ParseSessionSPDU(sessionData)
	if err != nil {
		t.Fatalf("ParseSessionSPDU failed: %v", err)
	}

	// Проверяем значения согласно комментарию
	if spdu.Type != SessionSPDUTypeAccept {
		t.Errorf("Expected Type ACCEPT (14), got %d", spdu.Type)
	}

	if spdu.Length != 0x86 {
		t.Errorf("Expected Length 134 (0x86), got %d", spdu.Length)
	}

	// Protocol Options: 0x00
	if spdu.ProtocolOptions != 0x00 {
		t.Errorf("Expected ProtocolOptions 0x00, got 0x%02x", spdu.ProtocolOptions)
	}

	// Version Number: 0x02
	if spdu.ProtocolVersion != 0x02 {
		t.Errorf("Expected ProtocolVersion 0x02, got 0x%02x", spdu.ProtocolVersion)
	}

	// Session Requirement: 0x0002
	if spdu.SessionRequirement != 0x0002 {
		t.Errorf("Expected SessionRequirement 0x0002, got 0x%04x", spdu.SessionRequirement)
	}

	// Called Session Selector: 0x0001
	expectedCalledSelector := []byte{0x00, 0x01}
	if len(spdu.CalledSessionSelector) != len(expectedCalledSelector) {
		t.Errorf("Expected CalledSessionSelector length %d, got %d", len(expectedCalledSelector), len(spdu.CalledSessionSelector))
	} else {
		for i, b := range expectedCalledSelector {
			if spdu.CalledSessionSelector[i] != b {
				t.Errorf("Expected CalledSessionSelector[%d] = 0x%02x, got 0x%02x", i, b, spdu.CalledSessionSelector[i])
			}
		}
	}

	// Session user data: 116 байт (0x74)
	expectedDataLength := 116
	if len(spdu.Data) != expectedDataLength {
		t.Errorf("Expected Data length %d, got %d", expectedDataLength, len(spdu.Data))
	} else {
		// Проверяем первые и последние байты данных
		expectedFirstBytes := []byte{0x31, 0x72, 0xa0, 0x03}
		expectedLastBytes := []byte{0x00, 0x40, 0xed, 0x18}
		for i, b := range expectedFirstBytes {
			if spdu.Data[i] != b {
				t.Errorf("Expected Data[%d] = 0x%02x, got 0x%02x", i, b, spdu.Data[i])
			}
		}
		for i, b := range expectedLastBytes {
			idx := len(spdu.Data) - len(expectedLastBytes) + i
			if spdu.Data[idx] != b {
				t.Errorf("Expected Data[%d] = 0x%02x, got 0x%02x", idx, b, spdu.Data[idx])
			}
		}
	}
}
