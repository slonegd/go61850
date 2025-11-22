# ACSE Package

Пакет `acse` реализует протокол ACSE (Association Control Service Element) согласно ISO 8650-1, используемый в IEC 61850 для управления ассоциациями между приложениями. Реализация основана на библиотеке `libIEC61850` (C).

## Основные концепции

### AARQ - Association Request
Клиент отправляет AARQ (Association Request) для установления ассоциации. Сообщение содержит:
- Application Context Name (имя контекста приложения, например, MMS)
- Called AP Title и AE Qualifier (адрес вызываемой стороны)
- Calling AP Title и AE Qualifier (адрес вызывающей стороны)
- User Information (данные пользователя для вышестоящих уровней, например, MMS PDU)
- Опционально: параметры аутентификации

### AARE - Association Response
Сервер отвечает AARE (Association Response), подтверждая или отклоняя ассоциацию. Сообщение содержит:
- Application Context Name
- Result (результат: accept, reject-permanent, reject-transient)
- Result Source Diagnostic (диагностика результата)
- User Information (данные пользователя, например, MMS PDU)

### Состояния соединения
ACSE соединение может находиться в следующих состояниях:
- `StateIdle` - бездействие
- `StateRequestIndicated` - запрос получен
- `StateConnected` - соединение установлено

## Быстрый старт

### Создание AARQ (Association Request)

```go
package main

import (
    "github.com/slonegd/go61850/osi/acse"
    "github.com/slonegd/go61850/osi/mms"
)

func main() {
    // 1. Создаём MMS PDU (данные пользователя)
    mmsPdu := mms.BuildInitiateRequestPDU()

    // 2. Создаём ACSE AARQ с параметрами по умолчанию
    aarq := acse.BuildAARQ(mmsPdu)

    // 3. Отправляем через Presentation/Session/COTP уровни
    // (см. примеры в пакете go61850)
}
```

### Создание AARQ с кастомными параметрами

```go
package main

import (
    "github.com/slonegd/go61850/osi/acse"
    "github.com/slonegd/go61850/osi/mms"
)

func main() {
    // Создаём ACSE соединение
    conn := acse.NewConnection()

    // Настраиваем параметры ISO соединения
    isoParams := &acse.IsoConnectionParameters{
        RemoteAPTitle:     []byte{0x29, 0x01, 0x87, 0x67, 0x01}, // OID вызываемой стороны
        RemoteAPTitleLen:  5,
        RemoteAEQualifier: 12,
        LocalAPTitle:      []byte{0x29, 0x01, 0x87, 0x67},      // OID вызывающей стороны
        LocalAPTitleLen:    4,
        LocalAEQualifier:  12,
    }

    // Создаём MMS PDU
    mmsPdu := mms.BuildInitiateRequestPDU()

    // Создаём AARQ с кастомными параметрами
    aarq := acse.CreateAssociateRequestMessage(conn, isoParams, mmsPdu, nil)

    // Отправляем через нижележащие уровни
}
```

### Парсинг входящих ACSE сообщений

```go
package main

import (
    "github.com/slonegd/go61850/osi/acse"
)

func handleACSE(acseData []byte) {
    conn := acse.NewConnection()
    
    indication, err := acse.ParseMessage(conn, acseData)
    if err != nil {
        log.Printf("Ошибка парсинга ACSE: %v", err)
        return
    }

    switch indication {
    case acse.IndicationAssociate:
        // Ассоциация успешно установлена
        // Получаем данные пользователя из conn.UserDataBuffer
        userData := conn.UserDataBuffer
        log.Printf("Получены данные пользователя: %d байт", len(userData))
        
    case acse.IndicationAssociateFailed:
        log.Println("Ассоциация отклонена")
        
    case acse.IndicationAbort:
        log.Println("Ассоциация прервана")
        
    case acse.IndicationReleaseRequest:
        log.Println("Запрос на освобождение ассоциации")
        
    case acse.IndicationReleaseResponse:
        log.Println("Подтверждение освобождения ассоциации")
        
    case acse.IndicationError:
        log.Println("Ошибка в ACSE сообщении")
    }
}
```

### Создание AARE (Association Response)

```go
package main

import (
    "github.com/slonegd/go61850/osi/acse"
    "github.com/slonegd/go61850/osi/mms"
)

func createAcceptResponse(conn *acse.Connection, mmsResponse []byte) []byte {
    // Создаём AARE с результатом "accept"
    aare := acse.CreateAssociateResponseMessage(
        conn,
        acse.ResultAccept,
        mmsResponse,
    )
    return aare
}

func createRejectResponse(conn *acse.Connection) []byte {
    // Создаём AARE с результатом "reject-permanent"
    aare := acse.CreateAssociateFailedMessage(conn, nil)
    return aare
}
```

## API Reference

### Типы

#### `Connection`
Представляет ACSE соединение и хранит его состояние.

```go
type Connection struct {
    State              ConnectionState
    NextReference      uint32
    UserDataBuffer     []byte
    UserDataBufferSize int
    ApplicationRef     ApplicationReference
}
```

**Поля:**
- `State` - текущее состояние соединения
- `NextReference` - следующий номер ссылки для user information
- `UserDataBuffer` - буфер с данными пользователя (например, MMS PDU)
- `UserDataBufferSize` - размер данных пользователя
- `ApplicationRef` - ISO application reference (AP Title и AE Qualifier)

#### `ConnectionState`
Состояние ACSE соединения.

```go
const (
    StateIdle ConnectionState = iota
    StateRequestIndicated
    StateConnected
)
```

#### `Indication`
Результат парсинга ACSE сообщения.

```go
const (
    IndicationError Indication = iota
    IndicationAssociate
    IndicationAssociateFailed
    IndicationOK
    IndicationAbort
    IndicationReleaseRequest
    IndicationReleaseResponse
)
```

#### `IsoConnectionParameters`
Параметры ISO соединения для создания AARQ.

```go
type IsoConnectionParameters struct {
    RemoteAPTitle     []byte
    RemoteAPTitleLen  int
    RemoteAEQualifier int32
    LocalAPTitle      []byte
    LocalAPTitleLen   int
    LocalAEQualifier  int32
}
```

**Поля:**
- `RemoteAPTitle` - OID вызываемой стороны (AP Title)
- `RemoteAPTitleLen` - длина OID вызываемой стороны
- `RemoteAEQualifier` - AE Qualifier вызываемой стороны
- `LocalAPTitle` - OID вызывающей стороны (AP Title)
- `LocalAPTitleLen` - длина OID вызывающей стороны
- `LocalAEQualifier` - AE Qualifier вызывающей стороны

#### `AuthenticationParameter`
Параметры аутентификации (опционально).

```go
type AuthenticationParameter struct {
    Mechanism   AuthenticationMechanism
    Password    []byte  // для AuthPassword
    Certificate []byte  // для AuthCertificate или AuthTLS
}
```

### Функции

#### `NewConnection() *Connection`
Создаёт новое ACSE соединение с начальным состоянием.

```go
conn := acse.NewConnection()
```

#### `BuildAARQ(userData []byte) []byte`
Создаёт AARQ (Association Request) PDU с параметрами по умолчанию.

**Параметры:**
- `userData` - данные пользователя (например, MMS PDU)

**Возвращает:**
- Байтовый массив, содержащий полностью сформированный AARQ PDU

**Пример:**
```go
mmsPdu := mms.BuildInitiateRequestPDU()
aarq := acse.BuildAARQ(mmsPdu)
```

**Параметры по умолчанию:**
- Application Context Name: MMS (1.0.9506.2.3)
- Called AP Title: 1.1.1.999.1
- Called AE Qualifier: 12
- Calling AP Title: 1.1.1.999
- Calling AE Qualifier: 12

#### `CreateAssociateRequestMessage(conn, isoParams, payload, authParam) []byte`
Создаёт AARQ (Association Request) PDU с кастомными параметрами.

**Параметры:**
- `conn` - ACSE соединение
- `isoParams` - параметры ISO соединения (AP Title, AE Qualifier)
- `payload` - данные пользователя (например, MMS PDU)
- `authParam` - параметры аутентификации (может быть `nil`)

**Возвращает:**
- Байтовый массив, содержащий полностью сформированный AARQ PDU

**Пример:**
```go
conn := acse.NewConnection()
isoParams := &acse.IsoConnectionParameters{
    RemoteAPTitle:     []byte{0x29, 0x01, 0x87, 0x67, 0x01},
    RemoteAPTitleLen:  5,
    RemoteAEQualifier: 12,
    LocalAPTitle:      []byte{0x29, 0x01, 0x87, 0x67},
    LocalAPTitleLen:    4,
    LocalAEQualifier:  12,
}
mmsPdu := mms.BuildInitiateRequestPDU()
aarq := acse.CreateAssociateRequestMessage(conn, isoParams, mmsPdu, nil)
```

#### `ParseMessage(conn, message) (Indication, error)`
Парсит входящее ACSE сообщение.

**Параметры:**
- `conn` - ACSE соединение (для хранения состояния)
- `message` - байтовый массив с ACSE сообщением

**Возвращает:**
- `Indication` - результат парсинга (IndicationAssociate, IndicationAssociateFailed, и т.д.)
- `error` - ошибка парсинга (если есть)

**Поддерживаемые типы сообщений:**
- `0x60` - AARQ (Association Request)
- `0x61` - AARE (Association Response)
- `0x62` - A_RELEASE.request
- `0x63` - A_RELEASE.response
- `0x64` - A_ABORT

**Пример:**
```go
conn := acse.NewConnection()
indication, err := acse.ParseMessage(conn, acseData)
if err != nil {
    log.Fatal(err)
}

if indication == acse.IndicationAssociate {
    // Ассоциация установлена
    userData := conn.UserDataBuffer
    // Обработка userData
}
```

#### `CreateAssociateResponseMessage(conn, acseResult, payload) []byte`
Создаёт AARE (Association Response) PDU.

**Параметры:**
- `conn` - ACSE соединение
- `acseResult` - результат ассоциации:
  - `acse.ResultAccept` (0) - принять
  - `acse.ResultRejectPermanent` (1) - отклонить постоянно
  - `acse.ResultRejectTransient` (2) - отклонить временно
- `payload` - данные пользователя (например, MMS PDU)

**Возвращает:**
- Байтовый массив, содержащий полностью сформированный AARE PDU

**Пример:**
```go
conn := acse.NewConnection()
mmsResponse := mms.BuildInitiateResponsePDU()
aare := acse.CreateAssociateResponseMessage(conn, acse.ResultAccept, mmsResponse)
```

#### `CreateAssociateFailedMessage(conn, payload) []byte`
Создаёт AARE с результатом "reject-permanent".

**Параметры:**
- `conn` - ACSE соединение
- `payload` - данные пользователя (может быть `nil`)

**Возвращает:**
- Байтовый массив, содержащий AARE PDU с отказом

**Пример:**
```go
conn := acse.NewConnection()
aare := acse.CreateAssociateFailedMessage(conn, nil)
```

#### `CreateAbortMessage(conn, isProvider) []byte`
Создаёт A_ABORT PDU для прерывания ассоциации.

**Параметры:**
- `conn` - ACSE соединение
- `isProvider` - `true` если прерывание от провайдера, `false` если от пользователя

**Возвращает:**
- Байтовый массив, содержащий A_ABORT PDU

#### `CreateReleaseRequestMessage(conn) []byte`
Создаёт A_RELEASE.request PDU.

**Параметры:**
- `conn` - ACSE соединение

**Возвращает:**
- Байтовый массив, содержащий A_RELEASE.request PDU

#### `CreateReleaseResponseMessage(conn) []byte`
Создаёт A_RELEASE.response PDU.

**Параметры:**
- `conn` - ACSE соединение

**Возвращает:**
- Байтовый массив, содержащий A_RELEASE.response PDU

## Интеграция с другими уровнями OSI

ACSE уровень находится между MMS и Presentation уровнями:

```
MMS → ACSE → Presentation → Session → COTP → TCP/IP
```

Пример использования в полном стеке:

```go
// 1. Создаём MMS PDU
mmsPdu := mms.BuildInitiateRequestPDU()

// 2. Обёртываем в ACSE AARQ
acsePdu := acse.BuildAARQ(mmsPdu)

// 3. Обёртываем в Presentation CP-type
presentationPdu := presentation.BuildCPType(acsePdu)

// 4. Обёртываем в Session CONNECT SPDU
sessionPdu := session.BuildConnectSPDU(presentationPdu)

// 5. Отправляем через COTP
err := cotpConn.SendDataMessage(sessionPdu)
```

## Структура AARQ PDU

AARQ PDU имеет следующую структуру:

```
AARQ (0x60)
├── Application Context Name (0xa1)
│   └── OID: 1.0.9506.2.3 (MMS)
├── Called AP Title (0xa2) [опционально]
│   └── OID вызываемой стороны
├── Called AE Qualifier (0xa3) [опционально]
│   └── INTEGER значение
├── Calling AP Title (0xa6) [опционально]
│   └── OID вызывающей стороны
├── Calling AE Qualifier (0xa7) [опционально]
│   └── INTEGER значение
├── Sender ACSE Requirements (0x8a) [опционально]
├── Mechanism Name (0x8b) [опционально]
│   └── OID механизма аутентификации
├── Authentication Value (0xac) [опционально]
│   └── Значение аутентификации
└── User Information (0xbe)
    └── Association Data (0x28)
        ├── Indirect Reference (0x02)
        │   └── INTEGER значение
        └── Encoding (0xa0)
            └── Single ASN1-type (данные пользователя, например, MMS PDU)
```

## Структура AARE PDU

AARE PDU имеет следующую структуру:

```
AARE (0x61)
├── Application Context Name (0xa1)
│   └── OID: 1.0.9506.2.3 (MMS)
├── Result (0xa2)
│   └── INTEGER (0 = accept, 1 = reject-permanent, 2 = reject-transient)
├── Result Source Diagnostic (0xa3)
│   └── Диагностическая информация
└── User Information (0xbe)
    └── Association Data (0x28)
        ├── Indirect Reference (0x02)
        │   └── INTEGER значение
        └── Encoding (0xa0)
            └── Single ASN1-type (данные пользователя, например, MMS PDU)
```

## Особенности реализации

### Кодирование BER
Реализация использует пакет `ber` для кодирования и декодирования BER-структур:
- Все теги и длины кодируются в BER формате
- Поддерживается кодирование OID (Object Identifier)
- Поддерживается кодирование INTEGER с правильным размером (1 байт для малых значений)

### Соответствие C библиотеке
Реализация следует логике библиотеки `libIEC61850`:
- Функции соответствуют функциям из `acse.c`:
  - `CreateAssociateRequestMessage` → `AcseConnection_createAssociateRequestMessage`
  - `ParseMessage` → `AcseConnection_parseMessage`
  - `CreateAssociateResponseMessage` → `AcseConnection_createAssociateResponseMessage`
- Структура `Connection` соответствует `AcseConnection` из `acse.h`
- Поддерживаются все основные типы ACSE PDU

### Кодирование малых INTEGER значений
Для малых значений INTEGER (0-127) используется кодирование в 1 байт, что соответствует BER спецификации и C библиотеке. Это важно для правильного кодирования AE Qualifier (обычно значение 12).

### Application Context Name
По умолчанию используется MMS Application Context Name:
- OID: `1.0.9506.2.3` (MMS)
- Закодировано как: `0x28, 0xca, 0x22, 0x02, 0x03`

## Примеры использования

### Полный цикл установления ассоциации

```go
package main

import (
    "log"
    "github.com/slonegd/go61850/osi/acse"
    "github.com/slonegd/go61850/osi/mms"
)

func establishAssociation() {
    // Клиентская сторона: создание AARQ
    mmsPdu := mms.BuildInitiateRequestPDU()
    aarq := acse.BuildAARQ(mmsPdu)
    
    // Отправка через нижележащие уровни...
    
    // Серверная сторона: парсинг AARQ
    conn := acse.NewConnection()
    indication, err := acse.ParseMessage(conn, aarq)
    if err != nil {
        log.Fatal(err)
    }
    
    if indication == acse.IndicationAssociate {
        // Ассоциация принята, создаём AARE
        mmsResponse := mms.BuildInitiateResponsePDU()
        aare := acse.CreateAssociateResponseMessage(
            conn,
            acse.ResultAccept,
            mmsResponse,
        )
        
        // Отправка AARE...
    }
}
```

### Обработка отказа в ассоциации

```go
func handleReject() {
    conn := acse.NewConnection()
    
    // Создаём AARE с отказом
    aare := acse.CreateAssociateFailedMessage(conn, nil)
    
    // Отправка AARE...
}
```

### Освобождение ассоциации

```go
func releaseAssociation(conn *acse.Connection) {
    // Запрос на освобождение
    releaseReq := acse.CreateReleaseRequestMessage(conn)
    
    // Отправка releaseReq...
    
    // После получения подтверждения:
    releaseResp := acse.CreateReleaseResponseMessage(conn)
    
    // Отправка releaseResp...
}
```

## Примечания

- Пакет реализует создание и парсинг основных ACSE PDU (AARQ, AARE, A_ABORT, A_RELEASE)
- Аутентификация поддерживается на уровне структуры данных, но callback-функция аутентификатора не реализована (может быть добавлена в будущем)
- Все значения по умолчанию соответствуют стандартным настройкам для IEC 61850
- Реализация основана на C библиотеке `libIEC61850` и соответствует её логике

## Ссылки

- ISO 8650-1: Information technology - Open Systems Interconnection - Connection-oriented protocol for the Association Control Service Element
- libIEC61850: [https://github.com/mzillgith/libIEC61850](https://github.com/mzillgith/libIEC61850)
- IEC 61850: Communication networks and systems for power utility automation

