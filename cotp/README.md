# COTP Package

Пакет `cotp` реализует протокол Connection-Oriented Transport Protocol (COTP) согласно ISO 8073, используемый в IEC 61850 для передачи данных поверх TCP/IP.

## Основные концепции

### Connection Request (CR) - Запрос соединения
Клиент отправляет Connection Request для инициализации COTP соединения. Сообщение содержит:
- Ссылки источника и назначения
- Параметры TPDU размера
- Транспортные селекторы (T-selectors)

### Connection Confirm (CC) - Подтверждение соединения
Сервер отвечает Connection Confirm, подтверждая установление соединения. Сообщение содержит:
- Подтвержденные ссылки
- Согласованные параметры соединения

### Data TPDU - Передача данных
После установления соединения данные передаются через Data TPDU. Большие сообщения автоматически фрагментируются.

## Быстрый старт

### Клиентская сторона (Connection Request)

```go
package main

import (
    "net"
    "github.com/slonegd/go61850/cotp"
)

func main() {
    // Подключение к серверу
    conn, err := net.Dial("tcp", "localhost:102")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    // Создание COTP соединения с параметрами по умолчанию
    cotpConn := cotp.NewConnection(conn)

    // Настройка параметров
    params := &cotp.IsoConnectionParameters{
        RemoteTSelector: cotp.TSelector{Value: []byte{0, 1}},
        LocalTSelector:  cotp.TSelector{Value: []byte{0, 1}},
    }

    // Отправка Connection Request
    if err := cotpConn.SendConnectionRequestMessage(params); err != nil {
        log.Fatal(err)
    }

    // Ожидание Connection Confirm
    for {
        state, err := cotpConn.ReadToTpktBuffer()
        if err != nil {
            log.Fatal(err)
        }

        if state == cotp.TpktPacketComplete {
            indication, err := cotpConn.ParseIncomingMessage()
            if err != nil {
                log.Fatal(err)
            }

            if indication == cotp.IndicationConnect {
                // Соединение установлено
                break
            }
        }
    }
}
```

### Серверная сторона (Connection Response)

```go
package main

import (
    "net"
    "github.com/slonegd/go61850/cotp"
)

func main() {
    listener, err := net.Listen("tcp", ":102")
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()

    for {
        conn, err := listener.Accept()
        if err != nil {
            continue
        }

        go handleConnection(conn)
    }
}

func handleConnection(conn net.Conn) {
    defer conn.Close()

    cotpConn := cotp.NewConnection(conn)

    // Ожидание Connection Request
    for {
        state, err := cotpConn.ReadToTpktBuffer()
        if err != nil {
            return
        }

        if state == cotp.TpktPacketComplete {
            indication, err := cotpConn.ParseIncomingMessage()
            if err != nil {
                return
            }

            if indication == cotp.IndicationConnect {
                // Отправка Connection Confirm
                if err := cotpConn.SendConnectionResponseMessage(); err != nil {
                    return
                }
                // Соединение установлено
                break
            }
        }
    }
}
```

## API Reference

### NewConnection

Создает новое COTP соединение.

```go
func NewConnection(conn io.ReadWriteCloser, opts ...ConnectionOption) *Connection
```

**Параметры:**
- `conn` - TCP или TLS соединение (обязательный)
- `opts` - опциональные параметры настройки

**Опции:**
- `WithPayloadBufferSize(size int)` - размер буфера для payload данных (по умолчанию: 8192)
- `WithReadBufferSize(size int)` - размер буфера для чтения TPKT пакетов (по умолчанию: 8192)
- `WithWriteBufferSize(size int)` - размер буфера для записи TPKT пакетов (по умолчанию: 8192)
- `WithSocketExtBufferSize(size int)` - размер extension буфера (по умолчанию: 8192)
- `WithLogger(logger Logger)` - логгер для отладки (по умолчанию: стандартный log с тегом [cotp])

**Примеры:**

```go
// Создание с параметрами по умолчанию
conn := cotp.NewConnection(tcpConn)

// Создание с кастомным логгером
conn := cotp.NewConnection(tcpConn, cotp.WithLogger(myLogger))

// Создание с кастомными размерами буферов
conn := cotp.NewConnection(tcpConn,
    cotp.WithPayloadBufferSize(16384),
    cotp.WithReadBufferSize(16384),
    cotp.WithWriteBufferSize(16384),
    cotp.WithLogger(myLogger),
)
```

### SendConnectionRequestMessage

Отправляет Connection Request (клиентская сторона).

```go
func (c *Connection) SendConnectionRequestMessage(params *IsoConnectionParameters) error
```

**Параметры:**
- `params` - параметры ISO соединения (T-selectors)

### SendConnectionResponseMessage

Отправляет Connection Confirm (серверная сторона).

```go
func (c *Connection) SendConnectionResponseMessage() error
```

### SendDataMessage

Отправляет данные через COTP. Автоматически фрагментирует большие сообщения.

```go
func (c *Connection) SendDataMessage(payload []byte) error
```

### ReadToTpktBuffer

Читает TPKT пакет из соединения.

```go
func (c *Connection) ReadToTpktBuffer() (TpktState, error)
```

**Возвращает:**
- `TpktPacketComplete` - пакет полностью прочитан
- `TpktWaiting` - ожидание дополнительных данных
- `TpktError` - ошибка чтения

### ParseIncomingMessage

Парсит входящее COTP сообщение.

```go
func (c *Connection) ParseIncomingMessage() (Indication, error)
```

**Возвращает:**
- `IndicationConnect` - Connection Request/Confirm получен
- `IndicationData` - данные получены (последний фрагмент)
- `IndicationMoreFragmentsFollow` - данные получены, ожидаются дополнительные фрагменты
- `IndicationDisconnect` - разрыв соединения
- `IndicationError` - ошибка

### GetPayload

Возвращает полученные данные.

```go
func (c *Connection) GetPayload() []byte
```

**Примечание:** После обработки данных вызовите `ResetPayload()` для очистки буфера.

### ResetPayload

Очищает буфер payload.

```go
func (c *Connection) ResetPayload()
```

### GetTpduSize / SetTpduSize

Управление размером TPDU.

```go
func (c *Connection) GetTpduSize() int
func (c *Connection) SetTpduSize(tpduSize int)
```

## Примеры использования

См. пакет `examples` для полных примеров использования:
- `examples.Client` - клиентская сторона (Connection Request)
- `examples.Server` - серверная сторона (Connection Response)
- `examples.Connection` - соединение на сервере для обмена данными

Примеры кода находятся в `examples/examples.go`:
- `ExampleClient` - клиентская сторона (Connection Request)
- `ExampleServer` - серверная сторона (Connection Response)
- `ExampleDataExchange` - обмен данными
- `ExampleDisconnect` - обработка разрыва соединения

Юнит-тесты с использованием клиента и сервера находятся в `examples/examples_test.go`.

## Типы данных

### Indication

Результат операции COTP:

```go
const (
    IndicationOK                  Indication = iota
    IndicationError
    IndicationConnect
    IndicationData
    IndicationDisconnect
    IndicationMoreFragmentsFollow
)
```

### TpktState

Состояние чтения TPKT пакета:

```go
const (
    TpktPacketComplete TpktState = iota
    TpktWaiting
    TpktError
)
```

### TSelector

Транспортный селектор:

```go
type TSelector struct {
    Value []byte
}
```

### IsoConnectionParameters

Параметры ISO соединения:

```go
type IsoConnectionParameters struct {
    RemoteTSelector TSelector
    LocalTSelector  TSelector
}
```

## Обработка ошибок

Все функции возвращают `error` в соответствии с Go-идиомами. Проверяйте ошибки после каждого вызова:

```go
if err := cotpConn.SendConnectionRequestMessage(params); err != nil {
    log.Fatalf("Failed to send connection request: %v", err)
}
```

## Фрагментация

Большие сообщения автоматически фрагментируются при отправке. При получении фрагментированных данных:

1. Получите `IndicationMoreFragmentsFollow` для промежуточных фрагментов
2. Получите `IndicationData` для последнего фрагмента
3. Используйте `GetPayload()` для получения полных данных

```go
for {
    indication, err := cotpConn.ParseIncomingMessage()
    if err != nil {
        log.Fatal(err)
    }

    switch indication {
    case cotp.IndicationMoreFragmentsFollow:
        // Продолжаем получать фрагменты
        continue
    case cotp.IndicationData:
        // Все фрагменты получены
        payload := cotpConn.GetPayload()
        // Обработка данных
        cotpConn.ResetPayload()
        break
    }
}
```

## Примечания

- COTP работает поверх TPKT (RFC 1006)
- Размер TPDU по умолчанию: 8192 байта
- Поддерживается автоматическая фрагментация больших сообщений
- Extension буфер используется для обработки случаев, когда TCP сокет не принимает все данные сразу

