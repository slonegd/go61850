package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/slonegd/go61850/osi/cotp"
)

// Эталонный пакет MMS Initiate Request из комментария в main.go
var expectedInitiatePacket = parseHexString(`
03 00 00 bb 02 f0 80 0d b2 05 06 13 01 00 16 01 02 14 02 00 02 33 02 00 01 34 02 00 01 c1 9c 31 81 99 a0 03 80 01 01 a2 81 91 81 04 00 00 00 01 82 04 00 00 00 01 a4 23 30 0f 02 01 01 06 04 52 01 00 01 30 04 06 02 51 01 30 10 02 01 03 06 05 28 ca 22 02 01 30 04 06 02 51 01 61 5e 30 5c 02 01 01 a0 57 60 55 a1 07 06 05 28 ca 22 02 03 a2 07 06 05 29 01 87 67 01 a3 03 02 01 0c a6 06 06 04 29 01 87 67 a7 03 02 01 0c be 2f 28 2d 02 01 03 a0 28 a8 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 04 08 00 00 79 ef 18
`)

// Эталонный пакет MMS Read Request из комментария в go61850.go
// 0300004e02f080010001006141303f020103a03aa038020101a433a131a02f302da02ba1291a1173696d706c65494f47656e65726963494f1a144747494f31244d5824416e496e31246d61672466
var expectedReadPacket = parseHexString(`
03 00 00 4e 02 f0 80 01 00 01 00 61 41 30 3f 02 01 03 a0 3a a0 38 02 01 01 a4 33 a1 31 a0 2f 30 2d a0 2b a1 29 1a 11 73 69 6d 70 6c 65 49 4f 47 65 6e 65 72 69 63 49 4f 1a 14 47 47 49 4f 31 24 4d 58 24 41 6e 49 6e 31 24 6d 61 67 24 66
`)

func TestProofOfConcept(t *testing.T) {
	// Создаём тестовый сервер
	server, err := newTestServer()
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer server.Stop()

	server.Start()

	// Небольшая задержка для запуска сервера
	time.Sleep(100 * time.Millisecond)

	// Создаём мок логгер
	mockLogger := &mockLogger{
		txMessages: make([]string, 0),
		txPackets:  make([][]byte, 0),
		rxMessages: make([]string, 0),
	}

	// Подключаемся к серверу
	conn, err := net.Dial("tcp", server.Addr())
	if err != nil {
		t.Fatalf("Failed to connect to test server: %v", err)
	}
	defer conn.Close()

	// Выполняем Proof of Concept (Initiate + ReadObject)
	err = proofOfConcept(conn, mockLogger)
	if err != nil {
		t.Fatalf("Proof of Concept failed: %v", err)
	}

	// Получаем все отправленные пакеты из логгера
	allPackets := mockLogger.getAllTXPackets()
	if len(allPackets) < 3 {
		t.Fatalf("Expected at least 3 packets (Connection Request, Initiate Request, Read Request), got %d", len(allPackets))
	}

	// Находим MMS Initiate Request (самый большой пакет, обычно > 180 байт)
	var initiatePacket []byte
	for _, pkt := range allPackets {
		if len(pkt) > 180 {
			initiatePacket = pkt
			break
		}
	}
	if initiatePacket == nil {
		t.Fatalf("Failed to find MMS Initiate Request packet")
	}

	// Проверяем MMS Initiate Request
	checkPacket(t, "MMS Initiate Request", initiatePacket, expectedInitiatePacket)

	// Находим MMS Read Request (пакет среднего размера, обычно 70-80 байт, после Initiate)
	var readPacket []byte
	for i := len(allPackets) - 1; i >= 0; i-- {
		pkt := allPackets[i]
		if len(pkt) > 50 && len(pkt) < 100 && len(pkt) != len(initiatePacket) {
			readPacket = pkt
			break
		}
	}
	if readPacket == nil {
		t.Fatalf("Failed to find MMS Read Request packet. All packets: %v", func() []int {
			sizes := make([]int, len(allPackets))
			for i, pkt := range allPackets {
				sizes[i] = len(pkt)
			}
			return sizes
		}())
	}

	// Проверяем MMS Read Request
	checkPacket(t, "MMS Read Request", readPacket, expectedReadPacket)

	// Проверяем, что ответ Read Response был успешно распарсен
	// proofOfConcept должен завершиться без ошибки, что означает успешный парсинг
	// Дополнительно проверяем, что в логах есть сообщение о результате ReadObject
	hasReadResult := false
	for _, msg := range mockLogger.rxMessages {
		if strings.Contains(msg, "ReadObject result:") {
			hasReadResult = true
			// Проверяем, что результат содержит ожидаемый формат AccessResult
			// Формат: &{Success:true Value:... Error:...}
			if !strings.Contains(msg, "Success:") || !strings.Contains(msg, "Value:") {
				t.Errorf("ReadObject result has unexpected format: %s", msg)
			}
			t.Logf("ReadObject result parsed successfully: %s", msg)
			break
		}
	}
	if !hasReadResult {
		t.Error("ReadObject result not found in logs - response may not have been parsed correctly")
	}
}

// checkPacket проверяет, что отправленный пакет совпадает с эталонным
func checkPacket(t *testing.T, packetName string, sentPacket, expectedPacket []byte) {
	// Побайтная проверка с эталонным пакетом
	if len(sentPacket) != len(expectedPacket) {
		t.Errorf("%s: Packet length mismatch: got %d bytes, expected %d bytes", packetName, len(sentPacket), len(expectedPacket))
		t.Logf("Sent packet:   % x", sentPacket)
		t.Logf("Expected packet: % x", expectedPacket)
		// Показываем различия
		minLen := len(sentPacket)
		if len(expectedPacket) < minLen {
			minLen = len(expectedPacket)
		}
		mismatches := 0
		for i := 0; i < minLen && mismatches < 20; i++ {
			if sentPacket[i] != expectedPacket[i] {
				if mismatches == 0 {
					t.Errorf("%s: Packet structure differences (first 20 mismatches):", packetName)
				}
				t.Errorf("  Byte %d: got %02x, expected %02x", i, sentPacket[i], expectedPacket[i])
				mismatches++
			}
		}
		return
	}

	// Побайтное сравнение
	mismatches := 0
	for i := 0; i < len(sentPacket); i++ {
		if sentPacket[i] != expectedPacket[i] {
			if mismatches == 0 {
				t.Errorf("%s: Packet does not match expected packet byte-by-byte:", packetName)
			}
			t.Errorf("  Byte %d: got %02x, expected %02x", i, sentPacket[i], expectedPacket[i])
			mismatches++
			if mismatches > 20 {
				t.Errorf("  ... (showing first 20 mismatches, total: %d)", mismatches)
				break
			}
		}
	}

	if mismatches == 0 {
		t.Logf("%s: Packet matches expected packet exactly (%d bytes)", packetName, len(sentPacket))
	} else {
		t.Errorf("%s: Total mismatches: %d out of %d bytes", packetName, mismatches, len(sentPacket))
		t.Logf("Sent packet:   % x", sentPacket)
		t.Logf("Expected packet: % x", expectedPacket)
	}
}

// mockLogger реализует logger.Logger и записывает все TX и RX сообщения
type mockLogger struct {
	txMessages []string
	txPackets  [][]byte
	rxMessages []string // Для проверки распарсенных ответов
}

func (m *mockLogger) Debug(format string, v ...any) {
	msg := fmt.Sprintf(format, v...)
	// Записываем TX сообщения (отправляемые пакеты)
	if strings.HasPrefix(msg, "TX:") {
		m.txMessages = append(m.txMessages, msg)
		// Извлекаем hex данные из сообщения
		// Формат: "TX: % x" -> "TX: 03 00 00 bb 02 f0 80 ..."
		parts := strings.Split(msg, " ")
		if len(parts) >= 2 {
			// Пропускаем "TX:" и берем остальное
			hexStr := strings.Join(parts[1:], "")
			// Парсим hex строку
			data := parseHexString(hexStr)
			if len(data) > 0 {
				m.txPackets = append(m.txPackets, data)
			}
		}
	}
	// Записываем сообщения о результатах (ReadObject result, InitiateResponse и т.д.)
	if strings.Contains(msg, "ReadObject result:") || strings.Contains(msg, "InitiateResponse:") {
		m.rxMessages = append(m.rxMessages, msg)
	}
}

// getLastTXPacket извлекает последний отправленный пакет (MMS Initiate Request)
func (m *mockLogger) getLastTXPacket() ([]byte, error) {
	if len(m.txPackets) == 0 {
		return nil, fmt.Errorf("no TX packets")
	}
	// Находим последний большой пакет (MMS Initiate Request, не Connection Request)
	// Connection Request обычно меньше 30 байт, MMS Initiate Request больше 100 байт
	for i := len(m.txPackets) - 1; i >= 0; i-- {
		if len(m.txPackets[i]) > 100 {
			return m.txPackets[i], nil
		}
	}
	// Если не нашли большой пакет, возвращаем последний
	if len(m.txPackets) > 0 {
		return m.txPackets[len(m.txPackets)-1], nil
	}
	return nil, fmt.Errorf("no suitable TX packet found")
}

// getAllTXPackets возвращает все отправленные пакеты
func (m *mockLogger) getAllTXPackets() [][]byte {
	return m.txPackets
}

// testServer представляет простой COTP сервер для тестирования
type testServer struct {
	listener net.Listener
	address  string
}

func newTestServer() (*testServer, error) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, err
	}
	return &testServer{
		listener: listener,
		address:  listener.Addr().String(),
	}, nil
}

func (s *testServer) Addr() string {
	return s.address
}

func (s *testServer) Start() {
	go s.acceptLoop()
}

func (s *testServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConnection(conn)
	}
}

func (s *testServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	cotpConn := cotp.NewConnection(conn)

	// Ожидание Connection Request
	if err := s.waitForConnectionRequest(cotpConn, 5*time.Second); err != nil {
		return
	}

	// Отправка Connection Confirm
	if err := cotpConn.SendConnectionResponseMessage(); err != nil {
		return
	}

	// Ожидание данных (MMS Initiate Request)
	if err := s.waitForData(cotpConn, 5*time.Second); err != nil {
		return
	}

	// Отправка правильного ответа (из комментария в go61850.go)
	// RX: 03 00 00 8f 02 f0 80 0e 86 05 06 13 01 00 16 01 02 14 02 00 02 34 02 00 01 c1 74 31 72 a0 03 80 01 01 a2 6b 83 04 00 00 00 01 a5 12 30 07 80 01 00 81 02 51 01 30 07 80 01 00 81 02 51 01 61 4f 30 4d 02 01 01 a0 48 61 46 a1 07 06 05 28 ca 22 02 03 a2 03 02 01 00 a3 05 a1 03 02 01 00 be 2f 28 2d 02 01 03 a0 28 a9 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 00 02 00 00 40 ed 18
	initiateResponse := parseHexString("03 00 00 8f 02 f0 80 0e 86 05 06 13 01 00 16 01 02 14 02 00 02 34 02 00 01 c1 74 31 72 a0 03 80 01 01 a2 6b 83 04 00 00 00 01 a5 12 30 07 80 01 00 81 02 51 01 30 07 80 01 00 81 02 51 01 61 4f 30 4d 02 01 01 a0 48 61 46 a1 07 06 05 28 ca 22 02 03 a2 03 02 01 00 a3 05 a1 03 02 01 00 be 2f 28 2d 02 01 03 a0 28 a9 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 00 02 00 00 40 ed 18")
	conn.Write(initiateResponse)

	// Ожидание Read Request и отправка Read Response
	// Формат ответа из комментария в go61850.go:
	// 0300002402f08001000100611730150201030a10a10e020101a409a1078705083edf52cc
	// Но в комментарии указано "0a10", что неправильно - должно быть "a010" для Context-specific 0, Constructed
	// Исправленный формат: 0300002402f0800100010061173015020103a010a10e020101a409a1078705083edf52cc
	if err := s.waitForData(cotpConn, 5*time.Second); err != nil {
		return
	}

	// Отправка Read Response (из комментария в go61850.go, исправленный формат)
	// TPKT: 03 00 00 24
	// COTP: 02 f0 80
	// Session: 01 00 01 00 (Give tokens + DT SPDU)
	// Presentation: 61 17 30 15 02 01 03 a0 10
	// MMS: a1 0e 02 01 01 a4 09 a1 07 87 05 08 3e df 52 cc
	readResponse := parseHexString("03 00 00 24 02 f0 80 01 00 01 00 61 17 30 15 02 01 03 a0 10 a1 0e 02 01 01 a4 09 a1 07 87 05 08 3e df 52 cc")
	conn.Write(readResponse)

	// Небольшая задержка перед закрытием соединения, чтобы клиент успел прочитать ответ
	time.Sleep(100 * time.Millisecond)
}

func (s *testServer) waitForConnectionRequest(cotpConn *cotp.Connection, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		select {
		case <-ticker.C:
			state, err := cotpConn.ReadToTpktBuffer(context.Background())
			if err != nil {
				if err == io.EOF {
					return fmt.Errorf("connection closed")
				}
				return fmt.Errorf("read error: %w", err)
			}

			if state == cotp.TpktWaiting {
				continue
			}

			if state == cotp.TpktError {
				return fmt.Errorf("tpkt error")
			}

			indication, err := cotpConn.ParseIncomingMessage()
			if err != nil {
				return fmt.Errorf("parse error: %w", err)
			}

			if indication == cotp.IndicationConnect {
				return nil
			}

			if indication == cotp.IndicationError {
				return fmt.Errorf("connection error")
			}
		}
	}

	return fmt.Errorf("connection timeout")
}

func (s *testServer) waitForData(cotpConn *cotp.Connection, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		select {
		case <-ticker.C:
			state, err := cotpConn.ReadToTpktBuffer(context.Background())
			if err != nil {
				if err == io.EOF {
					return fmt.Errorf("connection closed")
				}
				return fmt.Errorf("read error: %w", err)
			}

			if state == cotp.TpktWaiting {
				continue
			}

			if state == cotp.TpktError {
				return fmt.Errorf("tpkt error")
			}

			indication, err := cotpConn.ParseIncomingMessage()
			if err != nil {
				return fmt.Errorf("parse error: %w", err)
			}

			if indication == cotp.IndicationData {
				return nil
			}

			if indication == cotp.IndicationMoreFragmentsFollow {
				continue
			}
		}
	}

	return fmt.Errorf("data timeout")
}

func (s *testServer) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// parseHexString парсит hex строку из комментария
func parseHexString(hexStr string) []byte {
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, "\n", "")
	hexStr = strings.ReplaceAll(hexStr, "\t", "")
	data := make([]byte, 0, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		if i+1 >= len(hexStr) {
			break
		}
		var b byte
		if _, err := fmt.Sscanf(hexStr[i:i+2], "%02x", &b); err != nil {
			continue
		}
		data = append(data, b)
	}
	return data
}
