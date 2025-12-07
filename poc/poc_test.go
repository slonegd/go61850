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

// Эталонный пакет из комментария в main.go
// Полный пакет собирается из всех hex значений в комментарии
var expectedPacket = parseHexString(`
03 00 00 bb 02 f0 80 0d b2 05 06 13 01 00 16 01 02 14 02 00 02 33 02 00 01 34 02 00 01 c1 9c 31 81 99 a0 03 80 01 01 a2 81 91 81 04 00 00 00 01 82 04 00 00 00 01 a4 23 30 0f 02 01 01 06 04 52 01 00 01 30 04 06 02 51 01 30 10 02 01 03 06 05 28 ca 22 02 01 30 04 06 02 51 01 61 5e 30 5c 02 01 01 a0 57 60 55 a1 07 06 05 28 ca 22 02 03 a2 07 06 05 29 01 87 67 01 a3 03 02 01 0c a6 06 06 04 29 01 87 67 a7 03 02 01 0c be 2f 28 2d 02 01 03 a0 28 a8 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 04 08 00 00 79 ef 18
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
	}

	// Подключаемся к серверу
	conn, err := net.Dial("tcp", server.Addr())
	if err != nil {
		t.Fatalf("Failed to connect to test server: %v", err)
	}
	defer conn.Close()

	// Выполняем Proof of Concept
	err = proofOfConcept(conn, mockLogger)
	if err != nil {
		t.Fatalf("Proof of Concept failed: %v", err)
	}

	// Получаем отправленный пакет из логгера (MMS Initiate Request)
	sentPacket, err := mockLogger.getLastTXPacket()
	if err != nil {
		t.Fatalf("Failed to get sent packet from logger: %v", err)
	}

	// Побайтная проверка с эталонным пакетом
	if len(sentPacket) != len(expectedPacket) {
		t.Errorf("Packet length mismatch: got %d bytes, expected %d bytes", len(sentPacket), len(expectedPacket))
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
					t.Errorf("Packet structure differences (first 20 mismatches):")
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
				t.Errorf("Packet does not match expected packet byte-by-byte:")
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
		t.Logf("Packet matches expected packet exactly (%d bytes)", len(sentPacket))
	} else {
		t.Errorf("Total mismatches: %d out of %d bytes", mismatches, len(sentPacket))
		t.Logf("Sent packet:   % x", sentPacket)
		t.Logf("Expected packet: % x", expectedPacket)
	}
}

// mockLogger реализует logger.Logger и записывает все TX сообщения
type mockLogger struct {
	txMessages []string
	txPackets  [][]byte
}

func (m *mockLogger) Debug(format string, v ...any) {
	msg := fmt.Sprintf(format, v...)
	// Записываем только TX сообщения (отправляемые пакеты)
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
	response := parseHexString("03 00 00 8f 02 f0 80 0e 86 05 06 13 01 00 16 01 02 14 02 00 02 34 02 00 01 c1 74 31 72 a0 03 80 01 01 a2 6b 83 04 00 00 00 01 a5 12 30 07 80 01 00 81 02 51 01 30 07 80 01 00 81 02 51 01 61 4f 30 4d 02 01 01 a0 48 61 46 a1 07 06 05 28 ca 22 02 03 a2 03 02 01 00 a3 05 a1 03 02 01 00 be 2f 28 2d 02 01 03 a0 28 a9 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 00 02 00 00 40 ed 18")
	conn.Write(response)
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
