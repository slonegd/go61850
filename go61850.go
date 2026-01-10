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
	conn      net.Conn
	cotpConn  *cotp.Connection
	logger    logger.Logger
	mmsClient *mms.Client
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

// NewMmsClient создает новый MMS клиент и устанавливает COTP соединение.
// Контекст используется для установки COTP соединения, которое происходит
// при создании клиента. Параметры COTP соединения задаются значениями по умолчанию.
func NewMmsClient(ctx context.Context, conn net.Conn, opts ...MmsClientOption) (*MmsClient, error) {
	client := &MmsClient{
		conn:   conn,
		logger: defaultLogger(),
	}
	for _, opt := range opts {
		opt(client)
	}

	// Создаём COTP соединение и устанавливаем его
	params := &cotp.IsoConnectionParameters{
		RemoteTSelector: cotp.TSelector{Value: []byte{0, 1}},
		LocalTSelector:  cotp.TSelector{Value: []byte{0, 1}},
	}

	cotpConn, err := cotp.NewConnectedConnection(ctx, client.conn, params, cotp.WithLogger(client.logger))
	if err != nil {
		return nil, fmt.Errorf("failed to establish COTP connection: %w", err)
	}
	client.cotpConn = cotpConn

	// Создаём MMS клиент для работы с протокольным стеком
	client.mmsClient = mms.NewClient(client.cotpConn, client.logger)

	return client, nil
}

func (c *MmsClient) Initiate(ctx context.Context, opts ...mms.InitiateRequestOption) (*mms.InitiateResponse, error) {
	// --- Создание полного пакета MMS Initiate Request ---
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
	err := c.cotpConn.SendDataMessage(sessionPdu)
	if err != nil {
		return nil, fmt.Errorf("failed to send data: %w", err)
	}

	// --- Шаг 4: Получение ответа ---
	// Используем MMS клиент для получения и парсинга ответа
	mmsData, err := c.mmsClient.ReceiveAndParseMmsResponse(ctx)
	if err != nil {
		return nil, err
	}

	// Парсим MMS Initiate Response из данных ACSE
	if len(mmsData) == 0 {
		return nil, fmt.Errorf("MMS data is empty")
	}

	mmsResponse, err := mms.ParseInitiateResponse(mmsData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MMS Initiate Response: %w", err)
	}
	if mmsResponse == nil {
		return nil, fmt.Errorf("MMS Initiate Response is nil after parsing")
	}

	return mmsResponse, nil
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
// 5. Вернуть AccessResult с результатом чтения
func (c *MmsClient) ReadObject(ctx context.Context, readRequest *mms.ReadRequest) (mms.AccessResult, error) {
	var result mms.AccessResult
	// Проверяем, что соединение установлено
	if c.mmsClient == nil {
		return result, fmt.Errorf("connection not established, call Initiate first")
	}

	mmsPdu := readRequest.Bytes()

	// Логируем MMS PDU
	c.logger.Debug("MMS Read Request PDU: %x", mmsPdu)

	// Отправляем MMS PDU через стеки протоколов
	err := c.mmsClient.SendMmsPdu(mmsPdu)
	if err != nil {
		return result, fmt.Errorf("failed to send Read Request: %w", err)
	}

	// Получаем и парсим ответ
	mmsData, err := c.mmsClient.ReceiveAndParseMmsResponse(ctx)
	if err != nil {
		return result, err
	}

	c.logger.Debug("MMS Read Response PDU (raw bytes): %x", mmsData)

	// Парсим MMS Read Response
	if len(mmsData) == 0 {
		return result, fmt.Errorf("MMS data is empty")
	}

	readResponse, err := mms.ParseReadResponse(mmsData)
	if err != nil {
		return result, fmt.Errorf("failed to parse MMS Read Response: %w", err)
	}

	// Извлекаем значение из результатов
	if len(readResponse.ListOfAccessResult) == 0 {
		return result, fmt.Errorf("Read Response contains no access results")
	}

	// Берем первый результат (обычно запрашивается один объект)
	return readResponse.ListOfAccessResult[0], nil
}

// пример ответа через wireshark (не удалять)
// TPKT, Version: 3, Length: 297 03000129
// ISO 8073/X.224 COTP Connection-Oriented Transport Protocol 02f080
// ISO 8327-1 OSI Session Protocol 0100
// ISO 8327-1 OSI Session Protocol 0100
// ISO 8823 OSI Presentation Protocol 6182011a30820116020103a082010f
// MMS a182010b020102a6820104800100a281fea281fba181f8303c8005416e496e31a133a231a12f301a80036d6167a113a211a10f300d800166a108a7060201200201083008800171a1038401f33007800174a1029100303c8005416e496e32a133a231a12f301a80036d6167a113a211a10f300d800166a108a7060201200201083008800171a1038401f33007800174a1029100303c8005416e496e33a133a231a12f301a80036d6167a113a211a10f300d800166a108a7060201200201083008800171a1038401f33007800174a1029100303c8005416e496e34a133a231a12f301a80036d6167a113a211a10f300d800166a108a7060201200201083008800171a1038401f33007800174a1029100
// confirmed-ResponsePDU
//
//	invokeID: 2
//	confirmedServiceResponse: getVariableAccessAttributes (6)
//	  getVariableAccessAttributes
//	    mmsDeletable: False
//	    typeSpecification: structure (2)
//	      structure
//	        components: 4 items
//	          components item
//	            componentName: AnIn1
//	            componentType: structure (2)
//	              structure
//	                components: 3 items
//	                  components item
//	                    componentName: mag
//	                    componentType: structure (2)
//	                      structure
//	                        components: 1 item
//	                          components item
//	                            componentName: f
//	                  components item
//	                    componentName: q
//	                    componentType: bit-string (4)
//	                      bit-string: -13
//	                  components item
//	                    componentName: t
//	            componentName: AnIn2
//	            componentType: structure (2)
//	              structure
//	                components: 3 items
//	                  components item
//	                    componentName: mag
//	                    componentType: structure (2)
//	                      structure
//	                        components: 1 item
//	                          components item
//	                            componentName: f
//	                  components item
//	                    componentName: q
//	                    componentType: bit-string (4)
//	                      bit-string: -13
//	                  components item
//	                    componentName: t
//	            componentName: AnIn3
//	            componentType: structure (2)
//	              structure
//	                components: 3 items
//	                  components item
//	                    componentName: mag
//	                    componentType: structure (2)
//	                      structure
//	                        components: 1 item
//	                          components item
//	                            componentName: f
//	                  components item
//	                    componentName: q
//	                    componentType: bit-string (4)
//	                      bit-string: -13
//	                  components item
//	                    componentName: t
//	            componentName: AnIn4
//	            componentType: structure (2)
//	              structure
//	                components: 3 items
//	                  components item
//	                    componentName: mag
//	                    componentType: structure (2)
//	                      structure
//	                        components: 1 item
//	                          components item
//	                            componentName: f
//	                  components item
//	                    componentName: q
//	                    componentType: bit-string (4)
//	                      bit-string: -13
//	                  components item
//	                    componentName: t
func (c *MmsClient) GetTypeSpecification(ctx context.Context, readRequest *mms.ReadRequest) (*mms.TypeSpecification, error) {
	// Проверяем, что соединение установлено
	if c.mmsClient == nil {
		return nil, fmt.Errorf("connection not established, call Initiate first")
	}

	domainID := readRequest.DomainID
	itemID := readRequest.ItemID

	// Создаём запрос getVariableAccessAttributes
	getVarAccessAttrRequest := mms.NewGetVariableAccessAttributesRequest(domainID, itemID)
	mmsPdu := getVarAccessAttrRequest.Bytes()

	// Логируем MMS PDU
	c.logger.Debug("MMS GetVariableAccessAttributes Request PDU: %x", mmsPdu)

	// Отправляем MMS PDU через стеки протоколов
	err := c.mmsClient.SendMmsPdu(mmsPdu)
	if err != nil {
		return nil, fmt.Errorf("failed to send GetVariableAccessAttributes Request: %w", err)
	}

	// Получаем и парсим ответ
	mmsData, err := c.mmsClient.ReceiveAndParseMmsResponse(ctx)
	if err != nil {
		return nil, err
	}

	c.logger.Debug("MMS GetVariableAccessAttributes Response PDU (raw bytes): %x", mmsData)

	// Парсим MMS GetVariableAccessAttributes Response
	if len(mmsData) == 0 {
		return nil, fmt.Errorf("MMS data is empty")
	}

	// Парсим полный ответ GetVariableAccessAttributes, включая invokeID, mmsDeletable и typeSpecification
	response, err := mms.ParseGetVariableAccessAttributesResponse(mmsData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MMS GetVariableAccessAttributes Response: %w", err)
	}

	c.logger.Debug("  InvokeID: %d", response.InvokeID)
	c.logger.Debug("  MmsDeletable: %v", response.MmsDeletable)
	c.logger.Debug("  TypeSpecification: %+v", response.TypeSpecification)
	if response.TypeSpecification != nil && response.TypeSpecification.Structure != nil {
		c.logger.Debug("  Structure: %+v", response.TypeSpecification.Structure)
	}
	return response.TypeSpecification, nil
}
