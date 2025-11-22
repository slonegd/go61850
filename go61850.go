package go61850

import (
	"context"
	"fmt"
	"net"

	"github.com/slonegd/go61850/osi/acse"
	"github.com/slonegd/go61850/osi/cotp"
	"github.com/slonegd/go61850/osi/mms"
	"github.com/slonegd/go61850/osi/presentation"
	"github.com/slonegd/go61850/osi/session"
)

type MmsClient struct {
	conn     net.Conn
	cotpConn *cotp.Connection
	logger   cotp.Logger
}

// MmsClientOption представляет опцию для настройки MmsClient
type MmsClientOption func(*MmsClient)

// WithLogger устанавливает логгер для MmsClient
func WithLogger(logger cotp.Logger) MmsClientOption {
	return func(c *MmsClient) {
		c.logger = logger
	}
}

func NewMmsClient(conn net.Conn, opts ...MmsClientOption) *MmsClient {
	client := &MmsClient{
		conn: conn,
	}
	for _, opt := range opts {
		opt(client)
	}
	return client
}

func (c *MmsClient) Initiate(ctx context.Context) error {
	// Создаём COTP соединение
	ops := []cotp.ConnectionOption{}
	if c.logger != nil {
		ops = append(ops, cotp.WithLogger(c.logger))
	}
	c.cotpConn = cotp.NewConnection(c.conn, ops...)

	// --- Шаг 1: Отправка COTP CR TPDU ---
	params := &cotp.IsoConnectionParameters{
		RemoteTSelector: cotp.TSelector{Value: []byte{0, 1}},
		LocalTSelector:  cotp.TSelector{Value: []byte{0, 1}},
	}

	err := c.cotpConn.SendConnectionRequestMessage(params)
	if err != nil {
		return fmt.Errorf("failed to send COTP CR: %w", err)
	}

	// --- Шаг 2: Получение COTP CC TPDU ---
	for {
		// Проверяем контекст перед каждой итерацией цикла
		if ctx.Err() != nil {
			return ctx.Err()
		}

		state, err := c.cotpConn.ReadToTpktBuffer(ctx)
		if err != nil {
			return fmt.Errorf("failed to read TPKT: %w", err)
		}

		if state == cotp.TpktPacketComplete {
			indication, err := c.cotpConn.ParseIncomingMessage()
			if err != nil {
				return fmt.Errorf("failed to parse COTP message: %w", err)
			}

			if indication == cotp.IndicationConnect {
				break
			}
		} else if state == cotp.TpktError {
			return fmt.Errorf("TPKT read error")
		}
	}

	// --- Шаг 3: Создание полного пакета MMS Initiate Request ---
	// Порядок вложенности: MMS -> ACSE -> Presentation -> Session -> COTP

	// 1. Создаём MMS InitiateRequestPDU
	mmsPdu := mms.BuildInitiateRequestPDU()

	// 2. Обёртываем в ACSE AARQ
	acsePdu := acse.BuildAARQ(mmsPdu)

	// 3. Обёртываем в Presentation CP-type
	presentationPdu := presentation.BuildCPType(acsePdu)

	// 4. Обёртываем в Session CONNECT SPDU
	sessionPdu := session.BuildConnectSPDU(presentationPdu)

	// 5. Отправляем через COTP
	err = c.cotpConn.SendDataMessage(sessionPdu)
	if err != nil {
		return fmt.Errorf("failed to send data: %w", err)
	}

	// --- Шаг 4: Получение ответа ---
	for {
		// Проверяем контекст перед каждой итерацией цикла
		if ctx.Err() != nil {
			return ctx.Err()
		}

		state, err := c.cotpConn.ReadToTpktBuffer(ctx)
		if err != nil {
			return fmt.Errorf("failed to read TPKT: %w", err)
		}

		if state == cotp.TpktPacketComplete {
			indication, err := c.cotpConn.ParseIncomingMessage()
			if err != nil {
				return fmt.Errorf("failed to parse COTP message: %w", err)
			}

			if indication == cotp.IndicationData {
				c.cotpConn.ResetPayload()
				break
			} else if indication == cotp.IndicationMoreFragmentsFollow {
				// Продолжаем читать фрагменты
				continue
			}
		} else if state == cotp.TpktError {
			return fmt.Errorf("TPKT read error")
		}
	}

	return nil
}
