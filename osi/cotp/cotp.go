package cotp

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/slonegd/go61850/logger"
)

const (
	tpktRFC1006HeaderSize = 4
	cotpDataHeaderSize    = 3
	cotpMaxTpduSize       = 8192

	// Значения по умолчанию для буферов
	defaultPayloadBufferSize   = 8192
	defaultReadBufferSize      = 8192
	defaultWriteBufferSize     = 8192
	defaultSocketExtBufferSize = 8192
)

// connectionOptions содержит опции для создания Connection
type connectionOptions struct {
	payloadBufferSize   int
	readBufferSize      int
	writeBufferSize     int
	socketExtBufferSize int
	logger              logger.Logger
}

// defaultConnectionOptions возвращает опции по умолчанию
func defaultConnectionOptions() connectionOptions {
	return connectionOptions{
		payloadBufferSize:   defaultPayloadBufferSize,
		readBufferSize:      defaultReadBufferSize,
		writeBufferSize:     defaultWriteBufferSize,
		socketExtBufferSize: defaultSocketExtBufferSize,
		logger:              defaultLogger(),
	}
}

// defaultLogger создает логгер по умолчанию без категории
func defaultLogger() logger.Logger {
	return logger.NewLogger("")
}

// ConnectionOption представляет опцию для настройки Connection
type ConnectionOption func(*connectionOptions)

// WithPayloadBufferSize устанавливает размер буфера для payload
func WithPayloadBufferSize(size int) ConnectionOption {
	return func(opts *connectionOptions) {
		opts.payloadBufferSize = size
	}
}

// WithReadBufferSize устанавливает размер буфера для чтения
func WithReadBufferSize(size int) ConnectionOption {
	return func(opts *connectionOptions) {
		opts.readBufferSize = size
	}
}

// WithWriteBufferSize устанавливает размер буфера для записи
func WithWriteBufferSize(size int) ConnectionOption {
	return func(opts *connectionOptions) {
		opts.writeBufferSize = size
	}
}

// WithSocketExtBufferSize устанавливает размер extension буфера
func WithSocketExtBufferSize(size int) ConnectionOption {
	return func(opts *connectionOptions) {
		opts.socketExtBufferSize = size
	}
}

// WithLogger устанавливает логгер
func WithLogger(l logger.Logger) ConnectionOption {
	return func(opts *connectionOptions) {
		opts.logger = l
	}
}

// Indication представляет результат операции COTP
type Indication int

const (
	IndicationOK                  Indication = iota // Операция успешна
	IndicationError                                 // Ошибка
	IndicationConnect                               // Индикация подключения
	IndicationData                                  // Индикация данных
	IndicationDisconnect                            // Индикация отключения
	IndicationMoreFragmentsFollow                   // Следуют дополнительные фрагменты
)

// TpktState представляет состояние чтения TPKT пакета
type TpktState int

const (
	TpktPacketComplete TpktState = iota // Пакет полностью прочитан
	TpktWaiting                         // Ожидание данных
	TpktError                           // Ошибка чтения
)

// TSelector представляет транспортный селектор
type TSelector struct {
	Value []byte
}

// Options представляет опции COTP соединения
type Options struct {
	TSelSrc  TSelector
	TSelDst  TSelector
	TpduSize uint8 // Размер TPDU в виде степени двойки
}

// Connection представляет COTP соединение
type Connection struct {
	state           int
	remoteRef       int
	localRef        int
	protocolClass   int
	conn            io.ReadWriteCloser // TCP соединение или TLS соединение
	options         Options
	isLastDataUnit  bool
	payload         []byte        // Буфер для payload данных
	writeBuffer     []byte        // Буфер для записи TPKT пакета
	readBuffer      []byte        // Буфер для чтения TPKT пакета
	packetSize      uint16        // Размер текущего пакета
	socketExtBuffer []byte        // Буфер для данных, когда TCP сокет не принимает все данные
	socketExtFill   int           // Количество байт в extension буфере
	logger          logger.Logger // Логгер для отладки
}

// NewConnection создает новое COTP соединение
func NewConnection(conn io.ReadWriteCloser, opts ...ConnectionOption) *Connection {
	options := defaultConnectionOptions()
	for _, opt := range opts {
		opt(&options)
	}

	c := &Connection{
		state:           0,
		remoteRef:       -1,
		localRef:        1,
		protocolClass:   -1,
		conn:            conn,
		payload:         make([]byte, 0, options.payloadBufferSize),
		writeBuffer:     make([]byte, 0, options.writeBufferSize),
		readBuffer:      make([]byte, 0, options.readBufferSize),
		socketExtBuffer: make([]byte, 0, options.socketExtBufferSize),
		logger:          options.logger,
	}

	// Установка значений по умолчанию для TSelector
	tsel := TSelector{Value: []byte{0, 1}}
	c.options.TSelSrc = tsel
	c.options.TSelDst = tsel

	// Установка максимального размера TPDU по умолчанию
	c.SetTpduSize(cotpMaxTpduSize)

	return c
}

// NewConnectedConnection создает новое COTP соединение и устанавливает его (клиентская сторона).
// Это удобный конструктор, который объединяет создание соединения и установку подключения.
// Если нужно создать соединение без немедленного подключения, используйте NewConnection и затем вызовите Connect.
func NewConnectedConnection(ctx context.Context, conn io.ReadWriteCloser, params *IsoConnectionParameters, opts ...ConnectionOption) (*Connection, error) {
	c := NewConnection(conn, opts...)
	if err := c.Connect(ctx, params); err != nil {
		return nil, err
	}
	return c, nil
}

// GetTpduSize возвращает размер TPDU в байтах
func (c *Connection) GetTpduSize() int {
	return 1 << c.options.TpduSize
}

// SetTpduSize устанавливает размер TPDU в байтах
func (c *Connection) SetTpduSize(tpduSize int) {
	if tpduSize > cotpMaxTpduSize {
		tpduSize = cotpMaxTpduSize
	}

	newTpduSize := 1
	for (1 << newTpduSize) < tpduSize {
		newTpduSize++
	}

	if (1 << newTpduSize) > tpduSize {
		newTpduSize--
	}

	c.options.TpduSize = uint8(newTpduSize)
}

// GetRemoteRef возвращает удаленную ссылку
func (c *Connection) GetRemoteRef() int {
	return c.remoteRef
}

// GetLocalRef возвращает локальную ссылку
func (c *Connection) GetLocalRef() int {
	return c.localRef
}

// GetPayload возвращает payload буфер
func (c *Connection) GetPayload() []byte {
	return c.payload
}

// ResetPayload сбрасывает payload буфер
func (c *Connection) ResetPayload() {
	c.payload = c.payload[:0]
}

// FlushBuffer сбрасывает extension буфер
func (c *Connection) FlushBuffer() error {
	if c.socketExtFill > 0 {
		return c.flushBuffer()
	}
	return nil
}

// writeRfc1006Header записывает RFC 1006 заголовок
func (c *Connection) writeRfc1006Header(length int) {
	c.writeBuffer = c.writeBuffer[:0]
	c.writeBuffer = append(c.writeBuffer, 0x03, 0x00, byte(length>>8), byte(length&0xff))
}

// writeDataTpduHeader записывает заголовок Data TPDU
func (c *Connection) writeDataTpduHeader(isLastUnit bool) {
	c.writeBuffer = append(c.writeBuffer, 0x02, 0xf0)
	if isLastUnit {
		c.writeBuffer = append(c.writeBuffer, 0x80)
	} else {
		c.writeBuffer = append(c.writeBuffer, 0x00)
	}
}

// writeOptions записывает опции COTP
func (c *Connection) writeOptions() {
	if c.options.TpduSize != 0 {
		c.writeBuffer = append(c.writeBuffer, 0xc0, 0x01, c.options.TpduSize)
	}

	if len(c.options.TSelDst.Value) > 0 {
		c.writeBuffer = append(c.writeBuffer, 0xc2, byte(len(c.options.TSelDst.Value)))
		c.writeBuffer = append(c.writeBuffer, c.options.TSelDst.Value...)
	}

	if len(c.options.TSelSrc.Value) > 0 {
		c.writeBuffer = append(c.writeBuffer, 0xc1, byte(len(c.options.TSelSrc.Value)))
		c.writeBuffer = append(c.writeBuffer, c.options.TSelSrc.Value...)
	}
}

// getOptionsLength вычисляет длину опций
func (c *Connection) getOptionsLength() int {
	length := 0

	if c.options.TpduSize != 0 {
		length += 3
	}

	if len(c.options.TSelDst.Value) > 0 {
		length += 2 + len(c.options.TSelDst.Value)
	}

	if len(c.options.TSelSrc.Value) > 0 {
		length += 2 + len(c.options.TSelSrc.Value)
	}

	return length
}

// flushBuffer сбрасывает extension буфер в сокет
func (c *Connection) flushBuffer() error {
	if c.socketExtFill == 0 {
		return nil
	}

	n, err := c.conn.Write(c.socketExtBuffer[:c.socketExtFill])
	if err != nil {
		return err
	}

	if n < c.socketExtFill {
		// Перемещаем непереданные данные в начало буфера
		copy(c.socketExtBuffer, c.socketExtBuffer[n:c.socketExtFill])
		c.socketExtFill -= n
	} else {
		c.socketExtFill = 0
	}

	return nil
}

// sendBuffer отправляет буфер в сокет
func (c *Connection) sendBuffer() error {
	if err := c.flushBuffer(); err != nil {
		return err
	}

	if len(c.writeBuffer) == 0 {
		return nil
	}

	var n int
	var err error

	if c.socketExtFill == 0 {
		n, err = c.conn.Write(c.writeBuffer)
	} else {
		// Если extension буфер не пуст, добавляем данные туда
		err = nil
		n = 0
	}

	if err != nil {
		return err
	}

	if n < len(c.writeBuffer) {
		// Записываем оставшиеся данные в extension буфер
		remaining := c.writeBuffer[n:]
		if len(remaining)+c.socketExtFill > cap(c.socketExtBuffer) {
			return errors.New("socket extension buffer overflow")
		}

		c.socketExtBuffer = append(c.socketExtBuffer[:c.socketExtFill], remaining...)
		c.socketExtFill = len(c.socketExtBuffer)
	}

	c.writeBuffer = c.writeBuffer[:0]
	return nil
}

// IsoConnectionParameters представляет параметры ISO соединения
type IsoConnectionParameters struct {
	RemoteTSelector TSelector
	LocalTSelector  TSelector
}

// SendConnectionRequestMessage отправляет сообщение запроса соединения (клиентская сторона)
func (c *Connection) SendConnectionRequestMessage(params *IsoConnectionParameters) error {
	c.options.TSelDst = params.RemoteTSelector
	c.options.TSelSrc = params.LocalTSelector

	optionsLength := c.getOptionsLength()
	cotpRequestSize := optionsLength + 6
	conRequestSize := cotpRequestSize + 5

	if conRequestSize > cap(c.writeBuffer) {
		return fmt.Errorf("write buffer too small: need %d, have %d", conRequestSize, cap(c.writeBuffer))
	}

	c.writeRfc1006Header(conRequestSize)

	// LI
	c.writeBuffer = append(c.writeBuffer, byte(cotpRequestSize))

	// TPDU CODE
	c.writeBuffer = append(c.writeBuffer, 0xe0)

	// DST REF
	c.writeBuffer = append(c.writeBuffer, 0x00, 0x00)

	// SRC REF
	c.writeBuffer = append(c.writeBuffer, byte(c.localRef>>8), byte(c.localRef&0xff))

	// Class
	c.writeBuffer = append(c.writeBuffer, 0x00)

	c.writeOptions()

	// Логирование полного TPKT пакета перед отправкой
	if c.logger != nil {
		c.logger.Debug("TX: % x", c.writeBuffer)
	}

	return c.sendBuffer()
}

// SendConnectionResponseMessage отправляет сообщение ответа на соединение (серверная сторона)
func (c *Connection) SendConnectionResponseMessage() error {
	optionsLength := c.getOptionsLength()
	messageLength := 11 + optionsLength

	c.writeRfc1006Header(messageLength)

	// Заголовок ответа соединения
	c.writeBuffer = append(c.writeBuffer, byte(6+optionsLength), 0xd0,
		byte(c.remoteRef>>8), byte(c.remoteRef&0xff),
		byte(c.localRef>>8), byte(c.localRef&0xff),
		byte(c.protocolClass))

	c.writeOptions()

	// Логирование полного TPKT пакета перед отправкой
	if c.logger != nil {
		c.logger.Debug("TX: % x", c.writeBuffer)
	}

	return c.sendBuffer()
}

// Connect устанавливает COTP соединение (клиентская сторона).
// Отправляет Connection Request и ожидает Connection Confirm от сервера.
// Проверяет контекст перед каждой операцией чтения.
func (c *Connection) Connect(ctx context.Context, params *IsoConnectionParameters) error {
	// Отправляем Connection Request
	err := c.SendConnectionRequestMessage(params)
	if err != nil {
		return fmt.Errorf("failed to send COTP CR: %w", err)
	}

	// Ожидаем Connection Confirm
	for {
		// Проверяем контекст перед каждой итерацией цикла
		if ctx.Err() != nil {
			return ctx.Err()
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
		state, err := c.ReadToTpktBuffer(ctx)
		if err != nil {
			return fmt.Errorf("failed to read TPKT: %w", err)
		}

		if state == TpktPacketComplete {
			indication, err := c.ParseIncomingMessage()
			if err != nil {
				return fmt.Errorf("failed to parse COTP message: %w", err)
			}

			if indication == IndicationConnect {
				break
			}
		} else if state == TpktError {
			return errors.New("TPKT read error")
		}
	}

	return nil
}

// parseOptions парсит опции COTP
func (c *Connection) parseOptions(buffer []byte) error {
	bufPos := 0

	for bufPos < len(buffer) {
		if bufPos+1 >= len(buffer) {
			return errors.New("invalid option: missing type or length")
		}

		optionType := buffer[bufPos]
		optionLen := int(buffer[bufPos+1])
		bufPos += 2

		if bufPos+optionLen > len(buffer) {
			return fmt.Errorf("option too long: optionLen=%d, remaining=%d", optionLen, len(buffer)-bufPos)
		}

		switch optionType {
		case 0xc0: // TPDU size
			if optionLen == 1 {
				requestedTpduSize := 1 << buffer[bufPos]
				c.SetTpduSize(requestedTpduSize)
				bufPos++
			} else {
				return errors.New("invalid TPDU size option length")
			}

		case 0xc1: // remote T-selector
			if optionLen <= 16 {
				c.options.TSelSrc.Value = make([]byte, optionLen)
				copy(c.options.TSelSrc.Value, buffer[bufPos:bufPos+optionLen])
				bufPos += optionLen
			} else {
				return errors.New("t-selector too long")
			}

		case 0xc2: // local T-selector
			if optionLen <= 16 {
				c.options.TSelDst.Value = make([]byte, optionLen)
				copy(c.options.TSelDst.Value, buffer[bufPos:bufPos+optionLen])
				bufPos += optionLen
			} else {
				return errors.New("t-selector too long")
			}

		case 0xc6: // additional option selection
			if optionLen == 1 {
				bufPos++ // игнорируем значение
			} else {
				return errors.New("invalid additional option length")
			}

		default:
			// Игнорируем неизвестные опции
			bufPos += optionLen
		}
	}

	return nil
}

// parseConnectRequestTpdu парсит TPDU запроса соединения
func (c *Connection) parseConnectRequestTpdu(buffer []byte) error {
	if len(buffer) < 6 {
		return errors.New("connect request TPDU too short")
	}

	c.remoteRef = int(buffer[0])<<8 | int(buffer[1])
	c.protocolClass = int(buffer[4])

	return c.parseOptions(buffer[5:])
}

// parseConnectConfirmTpdu парсит TPDU подтверждения соединения
func (c *Connection) parseConnectConfirmTpdu(buffer []byte) error {
	if len(buffer) < 6 {
		return errors.New("connect confirm TPDU too short")
	}

	c.remoteRef = int(buffer[0])<<8 | int(buffer[1])
	c.protocolClass = int(buffer[4])

	return c.parseOptions(buffer[5:])
}

// parseDataTpdu парсит Data TPDU
func (c *Connection) parseDataTpdu(buffer []byte) error {
	if len(buffer) < 1 {
		return errors.New("data TPDU too short")
	}

	flowControl := buffer[0]
	c.isLastDataUnit = (flowControl & 0x80) != 0

	return nil
}

// addPayloadToBuffer добавляет payload в буфер
func (c *Connection) addPayloadToBuffer(buffer []byte) error {
	if len(buffer) == 0 {
		// Пустой payload допустим
		return nil
	}

	if len(c.payload)+len(buffer) > cap(c.payload) {
		return errors.New("payload buffer overflow")
	}

	c.payload = append(c.payload, buffer...)
	return nil
}

// parseCotpMessage парсит входящее COTP сообщение
func (c *Connection) parseCotpMessage() (Indication, error) {
	if len(c.readBuffer) < 4 {
		return IndicationError, errors.New("read buffer too short")
	}

	buffer := c.readBuffer[4:]
	tpduLength := len(c.readBuffer) - 4

	if len(buffer) == 0 {
		return IndicationError, errors.New("empty COTP message")
	}

	lenField := int(buffer[0])
	if lenField > tpduLength {
		return IndicationError, fmt.Errorf("invalid length: len=%d, tpduLength=%d", lenField, tpduLength)
	}

	if len(buffer) < 2 {
		return IndicationError, errors.New("COTP message too short")
	}

	tpduType := buffer[1]

	switch tpduType {
	case 0xe0: // Connect Request
		if err := c.parseConnectRequestTpdu(buffer[2:]); err != nil {
			return IndicationError, err
		}
		return IndicationConnect, nil

	case 0xd0: // Connect Confirm
		if err := c.parseConnectConfirmTpdu(buffer[2:]); err != nil {
			return IndicationError, err
		}
		return IndicationConnect, nil

	case 0xf0: // Data
		if err := c.parseDataTpdu(buffer[2:]); err != nil {
			return IndicationError, err
		}

		payloadStart := 3
		if payloadStart >= len(buffer) {
			return IndicationError, errors.New("data TPDU missing payload")
		}

		payloadData := buffer[payloadStart:]
		if err := c.addPayloadToBuffer(payloadData); err != nil {
			return IndicationError, err
		}

		if c.isLastDataUnit {
			return IndicationData, nil
		}
		return IndicationMoreFragmentsFollow, nil

	case 0x80: // Disconnect Request
		return IndicationDisconnect, nil

	case 0xc0: // Disconnect Confirm
		return IndicationDisconnect, nil

	default:
		return IndicationError, fmt.Errorf("unknown TPDU type: 0x%02x", tpduType)
	}
}

// ParseIncomingMessage парсит входящее сообщение
func (c *Connection) ParseIncomingMessage() (Indication, error) {
	// Логирование полного TPKT пакета перед парсингом
	if c.logger != nil && len(c.readBuffer) > 0 {
		c.logger.Debug("RX: % x", c.readBuffer)

		// Парсим TPKT и COTP для вывода в лог
		tpkt, err := ParseTPKT(c.readBuffer)
		if err == nil {
			c.logger.Debug("  %s", tpkt)

			// Парсим COTP из данных TPKT
			cotpPkt, err := ParseCOTP(tpkt.Data)
			if err == nil {
				c.logger.Debug("  %s", cotpPkt)
			}
		}
	}

	indication, err := c.parseCotpMessage()
	c.readBuffer = c.readBuffer[:0]
	c.packetSize = 0
	return indication, err
}

// SendDataMessage отправляет сообщение с данными
func (c *Connection) SendDataMessage(payload []byte) error {
	fragmentPayloadSize := c.GetTpduSize() - cotpDataHeaderSize

	fragments := 1
	if len(payload) > fragmentPayloadSize {
		fragments = len(payload) / fragmentPayloadSize
		if len(payload)%fragmentPayloadSize != 0 {
			fragments++
		}
	}

	// Вычисляем общий размер фрагментированного сообщения
	totalSize := fragments*(cotpDataHeaderSize+tpktRFC1006HeaderSize) + len(payload)

	// Проверяем, поместится ли в extension буфер
	if c.socketExtBuffer != nil {
		freeExtBufSize := cap(c.socketExtBuffer) - c.socketExtFill
		if freeExtBufSize < totalSize {
			return errors.New("total message size exceeds extension buffer capacity")
		}
	}

	// Пытаемся сбросить extension буфер
	if err := c.flushBuffer(); err != nil {
		return err
	}

	currentBufPos := 0

	for fragments > 0 {
		var currentLimit int
		var lastUnit bool

		if fragments > 1 {
			currentLimit = currentBufPos + fragmentPayloadSize
			lastUnit = false
		} else {
			currentLimit = len(payload)
			lastUnit = true
		}

		payloadFragment := payload[currentBufPos:currentLimit]
		fragmentSize := 7 + len(payloadFragment)

		c.writeRfc1006Header(fragmentSize)
		c.writeDataTpduHeader(lastUnit)
		c.writeBuffer = append(c.writeBuffer, payloadFragment...)

		// Логирование полного TPKT пакета перед отправкой
		if c.logger != nil {
			c.logger.Debug("TX: % x", c.writeBuffer)
		}

		if err := c.sendBuffer(); err != nil {
			return fmt.Errorf("failed to send fragment: %w", err)
		}

		currentBufPos = currentLimit
		fragments--
	}

	return nil
}

// ReadToTpktBuffer читает данные в TPKT буфер
// Проверяет контекст перед блокирующими операциями чтения
func (c *Connection) ReadToTpktBuffer(ctx context.Context) (TpktState, error) {
	if cap(c.readBuffer) < 4 {
		return TpktError, errors.New("read buffer too small")
	}

	// Проверяем контекст перед началом операции
	if ctx.Err() != nil {
		return TpktError, ctx.Err()
	}

	bufPos := len(c.readBuffer)

	// Сбрасываем extension буфер перед чтением
	if c.socketExtFill > 0 {
		if err := c.flushBuffer(); err != nil {
			return TpktError, err
		}
		if c.socketExtFill > 0 {
			return TpktWaiting, nil
		}
	}

	// Читаем TPKT заголовок (4 байта)
	if bufPos < 4 {
		// Проверяем контекст перед блокирующим чтением
		if ctx.Err() != nil {
			return TpktError, ctx.Err()
		}

		readBytes := make([]byte, 4-bufPos)
		n, err := c.conn.Read(readBytes)
		if err != nil {
			if err == io.EOF {
				return TpktError, errors.New("socket closed")
			}
			return TpktError, fmt.Errorf("read error: %w", err)
		}

		if n == 0 {
			return TpktWaiting, nil
		}

		c.readBuffer = append(c.readBuffer, readBytes[:n]...)
		bufPos = len(c.readBuffer)

		if bufPos == 4 {
			// Проверяем TPKT заголовок
			if c.readBuffer[0] != 0x03 || c.readBuffer[1] != 0x00 {
				return TpktError, errors.New("invalid TPKT header")
			}

			c.packetSize = uint16(c.readBuffer[2])<<8 | uint16(c.readBuffer[3])

			if int(c.packetSize) > cap(c.readBuffer) {
				return TpktError, fmt.Errorf("packet too large: %d bytes", c.packetSize)
			}
		} else {
			return TpktWaiting, nil
		}
	}

	// Читаем остаток пакета
	if c.packetSize == 0 {
		return TpktError, errors.New("packet size not set")
	}

	if bufPos >= int(c.packetSize) {
		// Пакет уже полностью прочитан
		return TpktPacketComplete, nil
	}

	// Проверяем контекст перед блокирующим чтением остатка пакета
	if ctx.Err() != nil {
		return TpktError, ctx.Err()
	}

	readBytes := make([]byte, int(c.packetSize)-bufPos)
	n, err := c.conn.Read(readBytes)
	if err != nil {
		if err == io.EOF {
			return TpktError, errors.New("socket closed")
		}
		return TpktError, fmt.Errorf("read error: %w", err)
	}

	if n == 0 {
		return TpktWaiting, nil
	}

	c.readBuffer = append(c.readBuffer, readBytes[:n]...)
	bufPos = len(c.readBuffer)

	if bufPos < int(c.packetSize) {
		return TpktWaiting, nil
	}

	// Пакет полностью прочитан
	return TpktPacketComplete, nil
}

// TPKT представляет TPKT (RFC 1006) пакет
type TPKT struct {
	Version  uint8  // Версия протокола (обычно 3)
	Reserved uint8  // Зарезервированное поле (обычно 0)
	Length   uint16 // Длина пакета в байтах
	Data     []byte // Данные следующего уровня (COTP)
}

// ParseTPKT парсит TPKT пакет из байтового буфера
func ParseTPKT(data []byte) (*TPKT, error) {
	if len(data) < 4 {
		return nil, errors.New("TPKT packet too short: need at least 4 bytes")
	}

	tpkt := &TPKT{
		Version:  data[0],
		Reserved: data[1],
		Length:   uint16(data[2])<<8 | uint16(data[3]),
	}

	if tpkt.Version != 0x03 {
		return nil, fmt.Errorf("invalid TPKT version: expected 0x03, got 0x%02x", tpkt.Version)
	}

	if tpkt.Reserved != 0x00 {
		return nil, fmt.Errorf("invalid TPKT reserved field: expected 0x00, got 0x%02x", tpkt.Reserved)
	}

	if int(tpkt.Length) < 4 {
		return nil, fmt.Errorf("invalid TPKT length: %d (must be at least 4)", tpkt.Length)
	}

	if len(data) < int(tpkt.Length) {
		return nil, fmt.Errorf("TPKT packet incomplete: need %d bytes, got %d", tpkt.Length, len(data))
	}

	// Данные следующего уровня (COTP) начинаются после заголовка TPKT
	tpkt.Data = make([]byte, int(tpkt.Length)-4)
	copy(tpkt.Data, data[4:tpkt.Length])

	return tpkt, nil
}

// String реализует интерфейс fmt.Stringer для TPKT
func (t *TPKT) String() string {
	return fmt.Sprintf("TPKT{Version: %d, Reserved: %d, Length: %d, DataLength: %d}",
		t.Version, t.Reserved, t.Length, len(t.Data))
}

// COTPType представляет тип COTP TPDU
type COTPType uint8

const (
	COTPTypeData              COTPType = 0xf0 // Data TPDU
	COTPTypeConnectionRequest COTPType = 0xe0 // Connection Request
	COTPTypeConnectionConfirm COTPType = 0xd0 // Connection Confirm
	COTPTypeDisconnectRequest COTPType = 0x80 // Disconnect Request
	COTPTypeDisconnectConfirm COTPType = 0xc0 // Disconnect Confirm
)

// COTP представляет COTP (ISO 8073/X.224) пакет
type COTP struct {
	Length         uint8    // Длина TPDU (без поля Length)
	Type           COTPType // Тип TPDU
	Flags          uint8    // Флаги (для Data TPDU: бит 7 = Last Data Unit)
	IsLastDataUnit bool     // Флаг последнего блока данных (для Data TPDU)
	// Поля для ConnectionConfirm и ConnectionRequest
	DestRef            uint16 // Destination reference (2 байта)
	SrcRef             uint16 // Source reference (2 байта)
	Class              uint8  // Class (4 старших бита из reference, биты 15-12)
	ExtendedFormats    bool   // Extended formats (бит 1 из reference)
	NoExplicitFlowCtrl bool   // No explicit flow control (бит 0 из reference)
	ProtocolClass      uint8  // Protocol class (для ConnectionConfirm/Request)
	TpduSize           uint8  // TPDU size (из параметра 0xc0)
	DstTSAP            []byte // Destination TSAP (из параметра 0xc2)
	SrcTSAP            []byte // Source TSAP (из параметра 0xc1)
	Data               []byte // Данные следующего уровня (Session)
}

// ParseCOTP парсит COTP пакет из байтового буфера
func ParseCOTP(data []byte) (*COTP, error) {
	if len(data) < 2 {
		return nil, errors.New("COTP packet too short: need at least 2 bytes")
	}

	cotp := &COTP{
		Length: data[0],
		Type:   COTPType(data[1]),
	}

	if int(cotp.Length) < 2 {
		return nil, fmt.Errorf("invalid COTP length: %d (must be at least 2)", cotp.Length)
	}

	// Для Data TPDU читаем флаги
	if cotp.Type == COTPTypeData {
		if len(data) < 3 {
			return nil, errors.New("COTP Data TPDU too short: need at least 3 bytes")
		}
		cotp.Flags = data[2]
		cotp.IsLastDataUnit = (cotp.Flags & 0x80) != 0

		// Данные следующего уровня начинаются после заголовка (3 байта: Length, Type, Flags)
		// Для Data TPDU Length указывает только на Type + Flags (минимум 2 байта)
		// Данные идут после заголовка до конца буфера (как в parseCotpMessage)
		dataStart := 3
		if dataStart < len(data) {
			cotp.Data = make([]byte, len(data)-dataStart)
			copy(cotp.Data, data[dataStart:])
		}
	} else if cotp.Type == COTPTypeConnectionConfirm || cotp.Type == COTPTypeConnectionRequest {
		// Для ConnectionConfirm и ConnectionRequest парсим заголовок и параметры
		if len(data) < 6 {
			return nil, errors.New("COTP Connection TPDU too short: need at least 6 bytes")
		}

		// Destination reference (2 байта)
		destRef := uint16(data[2])<<8 | uint16(data[3])
		cotp.DestRef = destRef

		// Source reference (2 байта)
		srcRef := uint16(data[4])<<8 | uint16(data[5])
		cotp.SrcRef = srcRef

		// Protocol class и битовые поля (1 байт после SrcRef)
		if len(data) >= 7 {
			flagsByte := data[6]
			cotp.ProtocolClass = flagsByte
			// Извлекаем битовые поля из этого байта
			// Class (биты 7-4)
			cotp.Class = uint8((flagsByte >> 4) & 0x0F)
			// Extended formats (бит 1)
			cotp.ExtendedFormats = (flagsByte & 0x02) != 0
			// No explicit flow control (бит 0)
			cotp.NoExplicitFlowCtrl = (flagsByte & 0x01) != 0
		}

		// Парсим параметры (начинаются с позиции 7)
		offset := 7
		for offset < len(data) && offset < int(cotp.Length)+1 {
			if offset+1 >= len(data) {
				break
			}

			paramType := data[offset]
			paramLength := int(data[offset+1])
			offset += 2

			if offset+paramLength > len(data) {
				break
			}

			switch paramType {
			case 0xc0: // TPDU size
				if paramLength == 1 {
					cotp.TpduSize = data[offset]
				}
				offset += paramLength

			case 0xc1: // Source TSAP
				if paramLength > 0 && paramLength <= 16 {
					cotp.SrcTSAP = make([]byte, paramLength)
					copy(cotp.SrcTSAP, data[offset:offset+paramLength])
				}
				offset += paramLength

			case 0xc2: // Destination TSAP
				if paramLength > 0 && paramLength <= 16 {
					cotp.DstTSAP = make([]byte, paramLength)
					copy(cotp.DstTSAP, data[offset:offset+paramLength])
				}
				offset += paramLength

			default:
				// Пропускаем неизвестные параметры
				offset += paramLength
			}
		}

		// Для ConnectionConfirm/Request данных следующего уровня нет
		cotp.Data = []byte{}
	} else {
		// Для других типов TPDU
		// все данные относятся к COTP (параметры соединения)
		// Данных следующего уровня (Session) нет
		cotp.Data = []byte{}
	}

	return cotp, nil
}

// String реализует интерфейс fmt.Stringer для COTP
func (c *COTP) String() string {
	typeStr := "Unknown"
	switch c.Type {
	case COTPTypeData:
		typeStr = "Data"
	case COTPTypeConnectionRequest:
		typeStr = "ConnectionRequest"
	case COTPTypeConnectionConfirm:
		typeStr = "ConnectionConfirm"
	case COTPTypeDisconnectRequest:
		typeStr = "DisconnectRequest"
	case COTPTypeDisconnectConfirm:
		typeStr = "DisconnectConfirm"
	}

	if c.Type == COTPTypeData {
		return fmt.Sprintf("COTP{Length: %d, Type: %s (0x%02x), Flags: 0x%02x, IsLastDataUnit: %v, DataLength: %d}",
			c.Length, typeStr, uint8(c.Type), c.Flags, c.IsLastDataUnit, len(c.Data))
	}

	if c.Type == COTPTypeConnectionConfirm || c.Type == COTPTypeConnectionRequest {
		tpduSizeStr := "N/A"
		if c.TpduSize > 0 {
			tpduSizeStr = fmt.Sprintf("%d", 1<<c.TpduSize)
		}
		return fmt.Sprintf("COTP{Length: %d, Type: %s (0x%02x), DestRef: 0x%04x, SrcRef: 0x%04x, Class: %d, ExtendedFormats: %v, NoExplicitFlowCtrl: %v, ProtocolClass: %d, TpduSize: %s, DstTSAP: %x, SrcTSAP: %x, DataLength: %d}",
			c.Length, typeStr, uint8(c.Type), c.DestRef, c.SrcRef, c.Class, c.ExtendedFormats, c.NoExplicitFlowCtrl, c.ProtocolClass, tpduSizeStr, c.DstTSAP, c.SrcTSAP, len(c.Data))
	}

	return fmt.Sprintf("COTP{Length: %d, Type: %s (0x%02x), DataLength: %d}",
		c.Length, typeStr, uint8(c.Type), len(c.Data))
}
