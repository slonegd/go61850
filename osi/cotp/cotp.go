package cotp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
)

// Logger интерфейс для логирования COTP пакетов
type Logger interface {
	Debug(format string, v ...any)
}

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
	logger              Logger
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

// defaultLogger создает логгер по умолчанию через стандартный пакет log
func defaultLogger() Logger {
	return &stdLogger{}
}

// stdLogger реализует Logger через стандартный пакет log
type stdLogger struct{}

func (l *stdLogger) Debug(format string, v ...any) {
	log.Printf("[cotp] "+format, v...)
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
func WithLogger(logger Logger) ConnectionOption {
	return func(opts *connectionOptions) {
		opts.logger = logger
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
	payload         []byte // Буфер для payload данных
	writeBuffer     []byte // Буфер для записи TPKT пакета
	readBuffer      []byte // Буфер для чтения TPKT пакета
	packetSize      uint16 // Размер текущего пакета
	socketExtBuffer []byte // Буфер для данных, когда TCP сокет не принимает все данные
	socketExtFill   int    // Количество байт в extension буфере
	logger          Logger // Логгер для отладки
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
