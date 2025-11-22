package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/slonegd/go61850/osi/cotp"
)

// Server представляет COTP сервер
type Server struct {
	listener net.Listener
	address  string
	handler  func(*Connection) error
	logger   cotp.Logger
}

// Addr возвращает адрес сервера
func (s *Server) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Connection представляет соединение на сервере
type Connection struct {
	conn     net.Conn
	cotpConn *cotp.Connection
}

// NewServer создает новый COTP сервер
func NewServer(address string) *Server {
	return &Server{
		address: address,
	}
}

// SetLogger устанавливает логгер для сервера
func (s *Server) SetLogger(logger cotp.Logger) {
	s.logger = logger
}

// SetHandler устанавливает обработчик входящих соединений
func (s *Server) SetHandler(handler func(*Connection) error) {
	s.handler = handler
}

// Start запускает сервер
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.address)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	s.listener = listener

	go s.acceptLoop()

	return nil
}

// acceptLoop принимает входящие соединения
func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		go s.handleConnection(conn)
	}
}

// handleConnection обрабатывает входящее соединение
func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	cotpConn := cotp.NewConnection(conn, cotp.WithLogger(s.logger))

	// Ожидание Connection Request
	if err := s.waitForConnectionRequest(cotpConn, 5*time.Second); err != nil {
		return
	}

	// Отправка Connection Confirm
	if err := cotpConn.SendConnectionResponseMessage(); err != nil {
		return
	}

	// Создание Connection для обработчика
	connection := &Connection{
		conn:     conn,
		cotpConn: cotpConn,
	}

	// Вызов обработчика
	if s.handler != nil {
		if err := s.handler(connection); err != nil {
			return
		}
	}
}

// waitForConnectionRequest ожидает Connection Request
func (s *Server) waitForConnectionRequest(cotpConn *cotp.Connection, timeout time.Duration) error {
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

// SendData отправляет данные через COTP
func (c *Connection) SendData(data []byte) error {
	return c.cotpConn.SendDataMessage(data)
}

// ReceiveData получает данные через COTP
func (c *Connection) ReceiveData(timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		select {
		case <-ticker.C:
			state, err := c.cotpConn.ReadToTpktBuffer(context.Background())
			if err != nil {
				if err == io.EOF {
					return nil, fmt.Errorf("connection closed")
				}
				return nil, fmt.Errorf("read error: %w", err)
			}

			if state == cotp.TpktWaiting {
				continue
			}

			if state == cotp.TpktError {
				return nil, fmt.Errorf("tpkt error")
			}

			indication, err := c.cotpConn.ParseIncomingMessage()
			if err != nil {
				return nil, fmt.Errorf("parse error: %w", err)
			}

			switch indication {
			case cotp.IndicationData:
				payload := c.cotpConn.GetPayload()
				result := make([]byte, len(payload))
				copy(result, payload)
				c.cotpConn.ResetPayload()
				return result, nil
			case cotp.IndicationMoreFragmentsFollow:
				continue
			case cotp.IndicationDisconnect:
				return nil, fmt.Errorf("connection disconnected")
			case cotp.IndicationError:
				return nil, fmt.Errorf("connection error")
			}
		}
	}

	return nil, fmt.Errorf("receive timeout")
}

// GetConnection возвращает COTP соединение
func (c *Connection) GetConnection() *cotp.Connection {
	return c.cotpConn
}

// Close закрывает соединение
func (c *Connection) Close() error {
	return c.conn.Close()
}

// Stop останавливает сервер
func (s *Server) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
