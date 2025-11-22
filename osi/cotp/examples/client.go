package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/slonegd/go61850/osi/cotp"
)

// Client представляет COTP клиента
type Client struct {
	conn     net.Conn
	cotpConn *cotp.Connection
	address  string
	log      Logger
}
type Logger interface {
	Debug(format string, v ...any)
}

// NewClient создает нового COTP клиента
func NewClient(address string, log Logger) *Client {
	return &Client{
		address: address,
		log:     log,
	}
}

// Connect устанавливает соединение с сервером
func (c *Client) Connect(ctx context.Context, params *cotp.IsoConnectionParameters) error {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", c.address)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	c.conn = conn
	c.cotpConn = cotp.NewConnection(conn, cotp.WithLogger(c.log))

	// Отправка Connection Request
	if err := c.cotpConn.SendConnectionRequestMessage(params); err != nil {
		conn.Close()
		return fmt.Errorf("failed to send connection request: %w", err)
	}

	// Ожидание Connection Confirm
	if err := c.waitForConnection(5 * time.Second); err != nil {
		conn.Close()
		return fmt.Errorf("failed to establish connection: %w", err)
	}

	return nil
}

// waitForConnection ожидает установления соединения
func (c *Client) waitForConnection(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		select {
		case <-ticker.C:
			state, err := c.cotpConn.ReadToTpktBuffer(context.Background())
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

			indication, err := c.cotpConn.ParseIncomingMessage()
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
func (c *Client) SendData(data []byte) error {
	if c.cotpConn == nil {
		return fmt.Errorf("not connected")
	}
	return c.cotpConn.SendDataMessage(data)
}

// ReceiveData получает данные через COTP
func (c *Client) ReceiveData(timeout time.Duration) ([]byte, error) {
	if c.cotpConn == nil {
		return nil, fmt.Errorf("not connected")
	}

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

// Close закрывает соединение
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// GetConnection возвращает COTP соединение
func (c *Client) GetConnection() *cotp.Connection {
	return c.cotpConn
}
