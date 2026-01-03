package go61850

import (
	"context"
	"fmt"
	"net"

	"github.com/slonegd/go61850/logger"
	"github.com/slonegd/go61850/osi/acse"
	"github.com/slonegd/go61850/osi/cotp"
	"github.com/slonegd/go61850/osi/mms"
	"github.com/slonegd/go61850/osi/presentation"
	"github.com/slonegd/go61850/osi/session"
)

type MmsClient struct {
	conn     net.Conn
	cotpConn *cotp.Connection
	logger   logger.Logger
}

// defaultLogger создает логгер по умолчанию без категории
func defaultLogger() logger.Logger {
	return logger.NewLogger("")
}

// MmsClientOption представляет опцию для настройки MmsClient
type MmsClientOption func(*MmsClient)

// WithLogger устанавливает логгер для MmsClient
func WithLogger(l logger.Logger) MmsClientOption {
	return func(c *MmsClient) {
		c.logger = l
	}
}

func NewMmsClient(conn net.Conn, opts ...MmsClientOption) *MmsClient {
	client := &MmsClient{
		conn:   conn,
		logger: defaultLogger(),
	}
	for _, opt := range opts {
		opt(client)
	}
	return client
}

func (c *MmsClient) Initiate(ctx context.Context, opts ...mms.InitiateRequestOption) (*mms.InitiateResponse, error) {
	// Создаём COTP соединение
	c.cotpConn = cotp.NewConnection(c.conn, cotp.WithLogger(c.logger))

	// --- Шаг 1: Отправка COTP CR TPDU ---
	params := &cotp.IsoConnectionParameters{
		RemoteTSelector: cotp.TSelector{Value: []byte{0, 1}},
		LocalTSelector:  cotp.TSelector{Value: []byte{0, 1}},
	}

	err := c.cotpConn.SendConnectionRequestMessage(params)
	if err != nil {
		return nil, fmt.Errorf("failed to send COTP CR: %w", err)
	}

	// --- Шаг 2: Получение COTP CC TPDU ---
	for {
		// Проверяем контекст перед каждой итерацией цикла
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		// ответ от сервера
		// RX: 03 00 00 16 11 d0 00 01 00 01 00 c0 01 0d c2 02 00 01 c1 02 00 01
		// TPKT, Version: 3, Length: 22
		// Version: 3 Reserved: 0 Length: 22
		// ISO 8073/X.224 COTP Connection-Oriented Transport Protocol
		// Length: 17
		// PDU Type: CC Connect Confirm (0x0d)
		// Destination reference: 0x0001
		// Source reference: 0x0001
		// 0000 .... = Class: 0
		// .... ..0. = Extended formats: False
		// .... ...0 = No explicit flow control: False
		// Parameter code: tpdu-size (0xc0)
		// Parameter length: 1
		// TPDU size: 8192
		// Parameter code: dst-tsap (0xc2)
		// Parameter length: 2
		// Destination TSAP: 0001
		// Parameter code: src-tsap (0xc1)
		// Parameter length: 2
		// Source TSAP: 0001
		state, err := c.cotpConn.ReadToTpktBuffer(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to read TPKT: %w", err)
		}

		if state == cotp.TpktPacketComplete {
			indication, err := c.cotpConn.ParseIncomingMessage()
			if err != nil {
				return nil, fmt.Errorf("failed to parse COTP message: %w", err)
			}

			if indication == cotp.IndicationConnect {
				break
			}
		} else if state == cotp.TpktError {
			return nil, fmt.Errorf("TPKT read error")
		}
	}

	// --- Шаг 3: Создание полного пакета MMS Initiate Request ---
	// Порядок вложенности: MMS -> ACSE -> Presentation -> Session -> COTP

	// 1. Создаём MMS InitiateRequest структуру с опциями
	mmsRequest := mms.NewInitiateRequest(opts...)

	// Логируем структуру
	c.logger.Debug("MMS InitiateRequest: %s", mmsRequest)

	// Получаем BER-кодированный пакет
	mmsPdu := mmsRequest.Bytes()

	// 2. Обёртываем в ACSE AARQ
	acsePdu := acse.BuildAARQ(mmsPdu)

	// 3. Обёртываем в Presentation CP-type
	presentationPdu := presentation.BuildCPType(acsePdu)

	// 4. Обёртываем в Session CONNECT SPDU
	sessionPdu := session.BuildConnectSPDU(presentationPdu)

	// 5. Отправляем через COTP
	err = c.cotpConn.SendDataMessage(sessionPdu)
	if err != nil {
		return nil, fmt.Errorf("failed to send data: %w", err)
	}

	// --- Шаг 4: Получение ответа ---
	for {
		// Проверяем контекст перед каждой итерацией цикла
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		// ответ от сервера
		// RX: 03 00 00 8f 02 f0 80 0e 86 05 06 13 01 00 16 01 02 14 02 00 02 34 02 00 01 c1 74 31 72 a0 03 80 01 01 a2 6b 83 04 00 00 00 01 a5 12 30 07 80 01 00 81 02 51 01 30 07 80 01 00 81 02 51 01 61 4f 30 4d 02 01 01 a0 48 61 46 a1 07 06 05 28 ca 22 02 03 a2 03 02 01 00 a3 05 a1 03 02 01 00 be 2f 28 2d 02 01 03 a0 28 a9 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 00 02 00 00 40 ed 18
		// Пример MMS Initiate Response PDU (после извлечения из ACSE):
		// a9 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 00 02 00 00 40 ed 18
		// где:
		// a9 - InitiateResponsePDU tag
		// 26 - длина (38 байт)
		// 80 03 00 fd e8 - localDetailCalled: 65000
		// 81 01 05 - negotiatedMaxServOutstandingCalling: 5
		// 82 01 05 - negotiatedMaxServOutstandingCalled: 5
		// 83 01 0a - negotiatedDataStructureNestingLevel: 10
		// a4 16 - mmsInitResponseDetail (длина 22 байта)
		//   80 01 01 - negotiatedVersionNumber: 1
		//   81 03 05 f1 00 - negotiatedParameterCBB: padding 5, битовая маска f100
		//   82 0c 03 ee 1c 00 00 00 02 00 00 40 ed 18 - servicesSupportedCalled: padding 3, битовая маска ee1c00000002000040ed18
		// Пример MMS Initiate Response PDU (после извлечения из ACSE):
		// a9 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 00 02 00 00 40 ed 18
		// где:
		// a9 - InitiateResponsePDU tag
		// 26 - длина (38 байт)
		// 80 03 00 fd e8 - localDetailCalled: 65000
		// 81 01 05 - negotiatedMaxServOutstandingCalling: 5
		// 82 01 05 - negotiatedMaxServOutstandingCalled: 5
		// 83 01 0a - negotiatedDataStructureNestingLevel: 10
		// a4 16 - mmsInitResponseDetail (длина 22 байта)
		//   80 01 01 - negotiatedVersionNumber: 1
		//   81 03 05 f1 00 - negotiatedParameterCBB: padding 5, битовая маска f100
		//   82 0c 03 ee 1c 00 00 00 02 00 00 40 ed 18 - servicesSupportedCalled: padding 3, битовая маска ee1c00000002000040ed18
		// TPKT, Version: 3, Length: 143
		// ISO 8073/X.224 COTP Connection-Oriented Transport Protocol
		// Length: 2
		// PDU Type: DT Data (0x0f)
		// [Destination reference: 0x130000]
		// .000 0000 = TPDU number: 0x00
		// 1... .... = Last data unit: Yes
		// ISO 8327-1 OSI Session Protocol
		// SPDU Type: ACCEPT (AC) SPDU (14)
		// Length: 134
		// Parameter type: Connect Accept Item (5)
		// Parameter length: 6
		// Protocol Options
		// Parameter type: Protocol Options (19)
		// Parameter length: 1
		// Flags: 0x00
		// .... ...0 = Able to receive extended concatenated SPDU: False
		// Version Number
		// Parameter type: Version Number (22)
		// Parameter length: 1
		// Flags: 0x02, Protocol Version 2
		// .... ..1. = Protocol Version 2: True
		// .... ...0 = Protocol Version 1: False
		// Parameter type: Session Requirement (20)
		// Parameter length: 2
		// Flags: 0x0002, Duplex functional unit
		// ..0. .... .... .... = Session exception report: False
		// ...0 .... .... .... = Data separation function unit: False
		// .... 0... .... .... = Symmetric synchronize function unit: False
		// .... .0.. .... .... = Typed data function unit: False
		// .... ..0. .... .... = Exception function unit: False
		// .... ...0 .... .... = Capability function unit: False
		// .... .... 0... .... = Negotiated release function unit: False
		// .... .... .0.. .... = Activity management function unit: False
		// .... .... ..0. .... = Resynchronize function unit: False
		// .... .... ...0 .... = Major resynchronize function unit: False
		// .... .... .... 0... = Minor resynchronize function unit: False
		// .... .... .... .0.. = Expedited data function unit: False
		// .... .... .... ..1. = Duplex functional unit: True
		// .... .... .... ...0 = Half-duplex functional unit: False
		// Called Session Selector
		// Parameter type: Called Session Selector (52)
		// Parameter length: 2
		// Called Session Selector: 0001
		// Session user data
		// Parameter type: Session user data (193)
		// Parameter length: 116
		// ISO 8823 OSI Presentation Protocol
		// CPA-PPDU
		// mode-selector
		// mode-value: normal-mode (1)
		// normal-mode-parameters
		// responding-presentation-selector: 00000001
		// presentation-context-definition-result-list: 2 items
		// Result-list item
		// result: acceptance (0)
		// transfer-syntax-name: 2.1.1 (basic-encoding)
		// Result-list item
		// result: acceptance (0)
		// transfer-syntax-name: 2.1.1 (basic-encoding)
		// user-data: fully-encoded-data (1)
		// fully-encoded-data: 1 item
		// PDV-list
		// presentation-context-identifier: 1 (id-as-acse)
		// presentation-data-values: single-ASN1-type (0)
		// ISO 8650-1 OSI Association Control Service
		// aare
		// aSO-context-name: 1.0.9506.2.3 (MMS)
		// result: accepted (0)
		// result-source-diagnostic: service-user (1)
		// service-user: null (0)
		// user-information: 1 item
		// Association-data
		// indirect-reference: 3
		// encoding: single-ASN1-type (0)
		// MMS
		// initiate-ResponsePDU
		// localDetailCalled: 65000
		// negociatedMaxServOutstandingCalling: 5
		// negociatedMaxServOutstandingCalled: 5
		// negociatedDataStructureNestingLevel: 10
		// mmsInitResponseDetail
		// negociatedVersionNumber: 1
		// Padding: 5
		// negociatedParameterCBB: f100
		// Padding: 3
		// servicesSupportedCalled: ee1c00000002000040ed18
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
		// Парсим и логируем Session SPDU из данных COTP
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
		c.logger.Debug("  %s", sessionPdu)

		// Парсим и логируем Presentation PDU из данных Session
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
		c.logger.Debug("  %s", presentationPdu)

		// Парсим и логируем ACSE PDU из данных Presentation
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
		c.logger.Debug("  %s", acsePdu)

		// Парсим MMS Initiate Response из данных ACSE
		if len(acsePdu.Data) == 0 {
			return nil, fmt.Errorf("ACSE PDU data is empty")
		}

		mmsResponse, err := mms.ParseInitiateResponse(acsePdu.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse MMS Initiate Response: %w", err)
		}
		if mmsResponse == nil {
			return nil, fmt.Errorf("MMS Initiate Response is nil after parsing")
		}

		return mmsResponse, nil
	}
}

// ReadObject читает объект из сервера IEC 61850 по имени объекта.
// Это плейсхолдер метод, который будет реализован позже.
//
// TODO: Реализовать метод чтения объекта:
// 1. После успешного Initiate необходимо отправить MMS Read Request PDU
// 2. В Read Request нужно создать VariableAccessSpecification:
//   - Разобрать строку objectName (например, "simpleIOGenericIO/GGIO1.AnIn1.mag.f") на компоненты:
//   - domainName: "simpleIOGenericIO"
//   - variableName: "GGIO1.AnIn1.mag.f" (может быть иерархической структурой)
//   - Создать ObjectName из domainName и itemName (имя переменной)
//   - VariableAccessSpecification должен содержать listOfVariable (CHOICE) с ObjectName
//
// 3. Отправить Read Request через MMS клиент:
//   - Использовать существующее COTP соединение (c.cotpConn), которое создаётся в Initiate
//   - Закодировать Read Request в BER
//   - Отправить через Session/Presentation/ACSE слои (аналогично Initiate)
//
// 4. Получить и распарсить Read Response:
//   - Прочитать ответ от сервера через c.cotpConn.ReadToTpktBuffer(ctx)
//   - Распарсить COTP -> Session -> Presentation -> ACSE -> MMS
//   - Распарсить BER кодировку Read Response PDU
//   - Извлечь значение из listOfAccessResult
//   - Для объекта типа AnIn1.mag.f значение должно быть типом Float (REAL в MMS)
//
// 5. Вернуть строковое представление результата для логирования
func (c *MmsClient) ReadObject(ctx context.Context, objectName string) (string, error) {
	// запрос снятый wireshark
	// TPKT, Version: 3, Length: 78
	// 0300004e
	// ISO 8073/X.224 COTP Connection-Oriented Transport Protocol
	// Length: 2, PDU Type: DT Data (0x0f)
	// [Destination reference: 0x20000]
	// .000 0000 = TPDU number: 0x00
	// 1... .... = Last data unit: Yes
	// 02f080
	// ISO 8327-1 OSI Session Protocol
	// SPDU Type: Give tokens PDU (1), Length: 0
	// 0100
	// ISO 8327-1 OSI Session Protocol
	// SPDU Type: DATA TRANSFER (DT) SPDU (1)
	// Length: 0
	// 0100
	// ISO 8823 OSI Presentation Protocol
	// 6141
	// user-data: fully-encoded-data (1)
	// fully-encoded-data: 1 item
	// PDV-list
	// 303а0201
	// presentation-context-identifier: 3 (mms-abstract-syntax-version1(1))
	// presentation-data-values: single-ASN1-type (0)
	// 03a03a
	// MMS confirmed-RequestPDU
	// a038
	// invokeID: 1
	// 020101
	// confirmedServiceRequest: read (4)
	// a433a131a02f
	// variableAccessSpecificatn: listOfVariable (0)
	// listOfVariable: 1 item
	// listOfVariable item
	// 302da02b
	// variableSpecification: name (0)
	// a129
	// name: domain-specific (1)
	// 1a11
	// domainId: simpleIOGenericIO
	// 1a14
	// itemId: GGIO1$MX$AnIn1$mag$f

	// ответ снятый wireshark
	// TPKT, Version: 3, Length: 36
	// 03000024
	// ISO 8073/X.224 COTP Connection-Oriented Transport Protocol
	// 02f080
	// ISO 8327-1 OSI Session Protocol: SPDU Type: Give tokens PDU (1), Length: 0
	// 0100
	// ISO 8327-1 OSI Session Protocol: SPDU Type: DATA TRANSFER (DT) SPDU (1), Length: 0
	// 0100
	// ISO 8823 OSI Presentation Protocol
	// 6117
	// user-data: fully-encoded-data (1)
	// fully-encoded-data: 1 item
	// PDV-list
	// 30150201
	// presentation-context-identifier: 3 (mms-abstract-syntax-version1(1))
	// 03
	// presentation-data-values: single-ASN1-type (0)
	// 0a10
	// MMS
	// a10e
	// confirmed-ResponsePDU
	// invokeID: 1
	// 020101
	// confirmedServiceResponse: read (4)
	// a409
	// read
	// a107
	// listOfAccessResult: 1 item
	// AccessResult: success (1)
	// 8705
	// success: floating-point (7)
	// floating-point: 083edf52cc

	// TODO: Реализовать чтение объекта
	// Пока просто возвращаем сообщение о том, что метод не реализован
	return fmt.Sprintf("ReadObject not implemented yet. Object: %s", objectName), nil
}
