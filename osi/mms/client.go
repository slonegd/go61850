package mms

import (
	"context"
	"fmt"

	"github.com/slonegd/go61850/logger"
	"github.com/slonegd/go61850/osi/acse"
	"github.com/slonegd/go61850/osi/cotp"
	"github.com/slonegd/go61850/osi/presentation"
	"github.com/slonegd/go61850/osi/session"
)

// Client представляет клиент для работы с MMS протоколом на уровне OSI стека.
// Инкапсулирует логику отправки и получения MMS PDU через стеки протоколов
// (Presentation -> Session -> COTP и обратно).
type Client struct {
	cotpConn *cotp.Connection
	logger   logger.Logger
}

// NewClient создаёт новый MMS клиент с указанными параметрами.
func NewClient(cotpConn *cotp.Connection, logger logger.Logger) *Client {
	return &Client{
		cotpConn: cotpConn,
		logger:   logger,
	}
}

// SendMmsPdu отправляет MMS PDU через стеки протоколов (Presentation -> Session -> COTP).
// Эта функция инкапсулирует общую логику отправки MMS PDU, которая используется
// в функциях ReadObject и GetTypeSpecification.
func (c *Client) SendMmsPdu(mmsPdu []byte) error {
	// Обёртываем в Presentation user-data
	// contextID = 3 для MMS (mms-abstract-syntax-version1)
	presentationPdu := presentation.BuildUserData(mmsPdu, 3)

	// Обёртываем в Session: Give tokens PDU + DT SPDU + Presentation PDU
	// Это соответствует структуре из wireshark: 01 00 01 00 <Presentation PDU>
	sessionPdu := session.BuildDataTransferWithTokens(presentationPdu)

	// Отправляем через COTP
	return c.cotpConn.SendDataMessage(sessionPdu)
}

// ExtractMmsDataFromPresentation извлекает MMS данные из уже распарсенной Presentation PDU.
// Эта функция определяет контекст (ACSE или MMS) и извлекает MMS данные соответствующим образом.
// Используется в функциях ReadObject и GetTypeSpecification для получения MMS данных из ответа.
func (c *Client) ExtractMmsDataFromPresentation(presentationPdu *presentation.PresentationPDU) ([]byte, error) {
	// Определяем, что содержится в Presentation PDU
	// После установления соединения данные могут идти напрямую как MMS PDU (contextId = 3)
	// или через ACSE (contextId = 1)
	if presentationPdu.PresentationContextId == 3 {
		// MMS context - данные идут напрямую как MMS PDU
		return presentationPdu.Data, nil
	} else if presentationPdu.PresentationContextId == 1 {
		// ACSE context - нужно парсить ACSE PDU
		if len(presentationPdu.Data) == 0 {
			return nil, fmt.Errorf("presentation PDU data is empty")
		}

		acsePdu, err := acse.ParseACSEPDU(presentationPdu.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ACSE PDU: %w", err)
		}
		if acsePdu == nil {
			return nil, fmt.Errorf("ACSE PDU is nil after parsing")
		}

		// Логируем результат парсинга
		if c.logger != nil {
			c.logger.Debug("  %s", acsePdu)
		}

		return acsePdu.Data, nil
	} else {
		return nil, fmt.Errorf("unknown presentation context ID: %d", presentationPdu.PresentationContextId)
	}
}

// ReceiveAndParseMmsResponse получает и парсит MMS ответ через стеки протоколов
// (COTP -> Session -> Presentation -> ACSE/MMS). Эта функция инкапсулирует общую логику
// получения ответа, которая используется в функциях ReadObject и GetTypeSpecification.
// Возвращает извлеченные MMS данные и ошибку.
func (c *Client) ReceiveAndParseMmsResponse(ctx context.Context) ([]byte, error) {
	for {
		// Проверяем контекст перед каждой итерацией цикла
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		state, err := c.cotpConn.ReadToTpktBuffer(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to read TPKT: %w", err)
		}

		if state == cotp.TpktError {
			return nil, fmt.Errorf("TPKT read error")
		}

		if state == cotp.TpktWaiting {
			continue
		}

		// state == cotp.TpktPacketComplete
		indication, err := c.cotpConn.ParseIncomingMessage()
		if err != nil {
			return nil, fmt.Errorf("failed to parse COTP message: %w", err)
		}

		if indication == cotp.IndicationMoreFragmentsFollow {
			// Продолжаем читать фрагменты
			continue
		}

		if indication != cotp.IndicationData {
			return nil, fmt.Errorf("unexpected COTP indication: %d", indication)
		}

		// indication == cotp.IndicationData
		// Получаем payload из COTP
		payload := c.cotpConn.GetPayload()
		// Сбрасываем payload в конце обработки
		defer c.cotpConn.ResetPayload()

		if len(payload) == 0 {
			return nil, fmt.Errorf("received empty COTP payload")
		}

		// Парсим Session SPDU
		sessionPdu, err := session.ParseSessionSPDU(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Session SPDU: %w", err)
		}
		if sessionPdu == nil {
			return nil, fmt.Errorf("session SPDU is nil after parsing")
		}

		// Логируем результат парсинга
		if c.logger != nil {
			c.logger.Debug("  %s", sessionPdu)
		}

		// Парсим Presentation PDU
		if len(sessionPdu.Data) == 0 {
			return nil, fmt.Errorf("session SPDU data is empty")
		}

		presentationPdu, err := presentation.ParsePresentationPDU(sessionPdu.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Presentation PDU: %w", err)
		}
		if presentationPdu == nil {
			return nil, fmt.Errorf("presentation PDU is nil after parsing")
		}

		// Логируем результат парсинга
		if c.logger != nil {
			c.logger.Debug("  %s", presentationPdu)
		}

		// Извлекаем MMS данные из Presentation PDU
		mmsData, err := c.ExtractMmsDataFromPresentation(presentationPdu)
		if err != nil {
			return nil, err
		}

		return mmsData, nil
	}
}
