package presentation

import (
	"testing"

	"github.com/slonegd/go61850/osi/session"
)

// Тест парсинга CPA-PPDU из комментария в go61850.go (строки 143-144)
// Пакет без уровней TPKT, COTP и Session
func TestParsePresentationPDU_AcceptFromComment(t *testing.T) {
	// Полный пакет из комментария (строка 143):
	// 03 00 00 8f 02 f0 80 0e 86 05 06 13 01 00 16 01 02 14 02 00 02 34 02 00 01 c1 74 31 72 a0 03 80 01 01 a2 6b 83 04 00 00 00 01 a5 12 30 07 80 01 00 81 02 51 01 30 07 80 01 00 81 02 51 01 61 4f 30 4d 02 01 01 a0 48 61 46 a1 07 06 05 28 ca 22 02 03 a2 03 02 01 00 a3 05 a1 03 02 01 00 be 2f 28 2d 02 01 03 a0 28 a9 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 00 02 00 00 40 ed 18
	//
	// TPKT: 03 00 00 8f (4 байта)
	// COTP: 02 f0 80 (3 байта)
	// Session SPDU: 0e 86 ... (до c1 74)
	// Presentation PDU начинается с байта 0x31 (после Session user data)

	fullPacket := []byte{
		0x03, 0x00, 0x00, 0x8f, // TPKT
		0x02, 0xf0, 0x80, // COTP
		// Session SPDU:
		0x0e,       // SPDU Type: ACCEPT (14)
		0x86,       // Length: 134
		0x05, 0x06, // Connect Accept Item, length: 6
		0x13, 0x01, 0x00, // Protocol Options (19), length: 1, value: 0x00
		0x16, 0x01, 0x02, // Version Number (22), length: 1, value: 0x02
		0x14, 0x02, 0x00, 0x02, // Session Requirement (20), length: 2, value: 0x0002
		0x34, 0x02, 0x00, 0x01, // Called Session Selector (52), length: 2, value: 0x0001
		0xc1, 0x74, // Session user data (193), length: 116 (0x74)
		// Presentation data (116 байт) начинается здесь:
		0x31, 0x72, 0xa0, 0x03, 0x80, 0x01, 0x01, 0xa2, 0x6b, 0x83, 0x04, 0x00, 0x00, 0x00, 0x01, 0xa5,
		0x12, 0x30, 0x07, 0x80, 0x01, 0x00, 0x81, 0x02, 0x51, 0x01, 0x30, 0x07, 0x80, 0x01, 0x00, 0x81,
		0x02, 0x51, 0x01, 0x61, 0x4f, 0x30, 0x4d, 0x02, 0x01, 0x01, 0xa0, 0x48, 0x61, 0x46, 0xa1, 0x07,
		0x06, 0x05, 0x28, 0xca, 0x22, 0x02, 0x03, 0xa2, 0x03, 0x02, 0x01, 0x00, 0xa3, 0x05, 0xa1, 0x03,
		0x02, 0x01, 0x00, 0xbe, 0x2f, 0x28, 0x2d, 0x02, 0x01, 0x03, 0xa0, 0x28, 0xa9, 0x26, 0x80, 0x03,
		0x00, 0xfd, 0xe8, 0x81, 0x01, 0x05, 0x82, 0x01, 0x05, 0x83, 0x01, 0x0a, 0xa4, 0x16, 0x80, 0x01,
		0x01, 0x81, 0x03, 0x05, 0xf1, 0x00, 0x82, 0x0c, 0x03, 0xee, 0x1c, 0x00, 0x00, 0x00, 0x02, 0x00,
		0x00, 0x40, 0xed, 0x18,
	}

	// Убираем TPKT и COTP, оставляем Session SPDU
	sessionData := fullPacket[7:] // Пропускаем первые 7 байт (TPKT + COTP)

	// Парсим Session SPDU, чтобы извлечь presentation данные
	sessionPdu, err := session.ParseSessionSPDU(sessionData)
	if err != nil {
		t.Fatalf("Failed to parse Session SPDU: %v", err)
	}

	// Presentation данные находятся в sessionPdu.Data
	if len(sessionPdu.Data) == 0 {
		t.Fatal("Session user data is empty")
	}

	// Проверяем, что данные начинаются с правильного тега
	if len(sessionPdu.Data) < 2 || sessionPdu.Data[0] != 0x31 {
		t.Fatalf("Invalid presentation data: expected 0x31 at start, got 0x%02x, length: %d", sessionPdu.Data[0], len(sessionPdu.Data))
	}

	// Проверяем ожидаемую длину (116 байт согласно комментарию)
	expectedLength := 116
	if len(sessionPdu.Data) != expectedLength {
		t.Logf("Warning: Session user data length is %d, expected %d", len(sessionPdu.Data), expectedLength)
	}

	presentationData := sessionPdu.Data

	// Парсим Presentation PDU
	pdu, err := ParsePresentationPDU(presentationData)
	if err != nil {
		t.Fatalf("ParsePresentationPDU failed: %v, data length: %d, first bytes: %02x %02x", err, len(presentationData), presentationData[0], presentationData[1])
	}

	// Проверяем значения согласно комментарию
	if pdu.Type != CPA {
		t.Errorf("Expected Type CPA-PPDU (0x31), got 0x%02x", uint8(pdu.Type))
	}

	// Mode value: 1 (normal-mode)
	if pdu.ModeValue != 1 {
		t.Errorf("Expected ModeValue 1, got %d", pdu.ModeValue)
	}

	// Responding Presentation Selector: 00000001
	expectedRespondingSelector := []byte{0x00, 0x00, 0x00, 0x01}
	if len(pdu.RespondingPresentationSelector) != len(expectedRespondingSelector) {
		t.Errorf("Expected RespondingPresentationSelector length %d, got %d", len(expectedRespondingSelector), len(pdu.RespondingPresentationSelector))
	} else {
		for i, b := range expectedRespondingSelector {
			if pdu.RespondingPresentationSelector[i] != b {
				t.Errorf("Expected RespondingPresentationSelector[%d] = 0x%02x, got 0x%02x", i, b, pdu.RespondingPresentationSelector[i])
			}
		}
	}

	// В CPA-PPDU AcseContextId не извлекается из context-definition-result-list
	// (он известен из предыдущего CP-type). Проверяем NextContextId из user-data.
	// Presentation context id (из user-data): 1 (id-as-acse)
	if pdu.PresentationContextId != 1 {
		t.Errorf("Expected PresentationContextId 1, got %d", pdu.PresentationContextId)
	}

	// Presentation data values type: 0 (single-ASN1-type)
	if pdu.PresentationDataValuesType != 0 {
		t.Errorf("Expected PresentationDataValuesType 0, got %d", pdu.PresentationDataValuesType)
	}

	// AcseContextId может быть 0 в CPA-PPDU, так как он не извлекается из context-definition-result-list
	// В реальном использовании AcseContextId известен из предыдущего CP-type
	if pdu.AcseContextId == 0 {
		t.Logf("Note: AcseContextId is 0 in CPA-PPDU (expected, as it's not in context-definition-result-list)")
	}

	// Presentation user data: 72 байта (0x48 = 72)
	expectedDataLength := 72
	if len(pdu.Data) != expectedDataLength {
		t.Errorf("Expected Data length %d, got %d", expectedDataLength, len(pdu.Data))
	} else {
		// Проверяем первые и последние байты данных (ACSE)
		expectedFirstBytes := []byte{0x61, 0x46, 0xa1, 0x07}
		expectedLastBytes := []byte{0x00, 0x40, 0xed, 0x18}
		for i, b := range expectedFirstBytes {
			if pdu.Data[i] != b {
				t.Errorf("Expected Data[%d] = 0x%02x, got 0x%02x", i, b, pdu.Data[i])
			}
		}
		for i, b := range expectedLastBytes {
			idx := len(pdu.Data) - len(expectedLastBytes) + i
			if pdu.Data[idx] != b {
				t.Errorf("Expected Data[%d] = 0x%02x, got 0x%02x", idx, b, pdu.Data[idx])
			}
		}
	}
}

