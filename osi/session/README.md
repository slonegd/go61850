# Session Package

Пакет `session` реализует протокол ISO 8327-1 OSI Session Protocol, используемый в IEC 61850 для управления коммуникационными сеансами между приложениями. Реализация основана на библиотеке `libIEC61850` (C).

## Основные концепции

### CONNECT SPDU - Установление сессии
Клиент отправляет CONNECT SPDU для инициализации сеанса. Сообщение содержит:
- Connect Accept Item (параметры протокола и версия)
- Session Requirement (требования к сессии, например, дуплексный режим)
- Calling Session Selector (селектор вызывающей стороны)
- Called Session Selector (селектор вызываемой стороны)
- Session User Data (данные пользователя для вышестоящих уровней)

### Структура Session
Внутренняя структура `Session` хранит состояние сессии:
- `callingSessionSelector` - селектор вызывающей стороны
- `calledSessionSelector` - селектор вызываемой стороны
- `sessionRequirement` - требования к сессии (по умолчанию 0x0002 - дуплексный функциональный блок)
- `protocolOptions` - опции протокола (по умолчанию 0)

## Быстрый старт

### Создание CONNECT SPDU

```go
package main

import (
    "github.com/slonegd/go61850/osi/session"
)

func main() {
    // Данные от вышестоящих уровней (например, Presentation PDU)
    presentationData := []byte{0x31, 0x81, 0x99, /* ... */}

    // Создание CONNECT SPDU с параметрами по умолчанию
    connectSPDU := session.BuildConnectSPDU(presentationData)

    // Отправка через COTP соединение
    // (см. примеры в пакете cotp)
}
```

### Использование с кастомными параметрами

```go
package main

import (
    "github.com/slonegd/go61850/osi/session"
)

func main() {
    // Создание сессии с параметрами по умолчанию
    sess := session.NewSession()
    
    // Параметры по умолчанию:
    // - sessionRequirement = 0x0002 (duplex functional unit)
    // - callingSessionSelector = [0, 1]
    // - calledSessionSelector = [0, 1]
    // - protocolOptions = 0

    // Данные от вышестоящих уровней
    userData := []byte{/* ... */}

    // Использование внутренней функции для создания SPDU
    // (в текущей реализации BuildConnectSPDU использует NewSession() внутри)
    connectSPDU := session.BuildConnectSPDU(userData)
}
```

## API Reference

### Типы

#### `SSelector`
Селектор сессии, используемый для идентификации сессии.

```go
type SSelector struct {
    Value []byte
}
```

#### `Session`
Внутренняя структура, представляющая состояние сессии ISO 8327-1.

```go
type Session struct {
    callingSessionSelector SSelector
    calledSessionSelector  SSelector
    sessionRequirement     uint16
    protocolOptions        uint8
}
```

### Функции

#### `NewSession() *Session`
Создаёт новую сессию с параметрами по умолчанию:
- `sessionRequirement = 0x0002` (duplex functional unit)
- `callingSessionSelector = [0, 1]`
- `calledSessionSelector = [0, 1]`
- `protocolOptions = 0`

Эти значения соответствуют функции `IsoSession_init` из C библиотеки `libIEC61850`.

#### `BuildConnectSPDU(userData []byte) []byte`
Создаёт CONNECT SPDU (Session Protocol Data Unit) для установления сессии.

**Параметры:**
- `userData` - данные от вышестоящих уровней (например, Presentation PDU)

**Возвращает:**
- Байтовый массив, содержащий полностью сформированный CONNECT SPDU

**Реализация:**
Функция основана на `IsoSession_createConnectSpdu` из C библиотеки (строки 335-367 в `iso_session.c`). Использует значения по умолчанию, соответствующие `IsoSession_init`.

**Структура создаваемого SPDU:**
1. SPDU Type: `0x0D` (CONNECT)
2. Length: вычисляется автоматически
3. Connect Accept Item (8 байт):
   - Parameter type: `0x05` (Connect Accept Item)
   - Parameter length: `0x06`
   - Protocol Options: `0x13 0x01 0x00`
   - Version Number: `0x16 0x01 0x02` (Version 2)
4. Session Requirement (4 байта):
   - Parameter type: `0x14`
   - Parameter length: `0x02`
   - Flags: `0x00 0x02` (duplex functional unit)
5. Calling Session Selector (4 байта):
   - Parameter type: `0x33`
   - Parameter length: `0x02`
   - Value: `0x00 0x01`
6. Called Session Selector (4 байта):
   - Parameter type: `0x34`
   - Parameter length: `0x02`
   - Value: `0x00 0x01`
7. Session User Data:
   - Parameter type: `0xC1`
   - Parameter length: длина `userData` (короткий формат для значений <= 255)
   - User Data: содержимое `userData`

## Внутренние функции кодирования

Пакет содержит приватные функции кодирования, соответствующие функциям из C библиотеки:

- `encodeConnectAcceptItem` - кодирует Connect Accept Item (соответствует строкам 259-272 в `iso_session.c`)
- `encodeSessionRequirement` - кодирует Session Requirement (строки 289-298)
- `encodeCallingSessionSelector` - кодирует Calling Session Selector (строки 300-311)
- `encodeCalledSessionSelector` - кодирует Called Session Selector (строки 313-324)
- `encodeSessionUserData` - кодирует Session User Data (строки 326-333)

## Интеграция с другими уровнями OSI

Session уровень находится между Presentation и COTP уровнями:

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

## Особенности реализации

### Кодирование длины параметров
В Session Protocol длина параметра кодируется в коротком формате даже для значений >= 128 (в отличие от BER, где используется длинный формат). Это соответствует спецификации ISO 8327-1.

### Соответствие C библиотеке
Реализация следует логике библиотеки `libIEC61850`:
- Структура `Session` соответствует `IsoSession` из `iso_session.h`
- Функции кодирования соответствуют функциям из `iso_session.c`
- Значения по умолчанию соответствуют `IsoSession_init`

## Примечания

- Пакет реализует только создание CONNECT SPDU (клиентская сторона)
- Парсинг входящих SPDU и создание других типов SPDU (ACCEPT, REFUSE, ABORT, FINISH, DISCONNECT) могут быть добавлены в будущем
- Все значения по умолчанию соответствуют стандартным настройкам для IEC 61850

## Ссылки

- ISO 8327-1: OSI Session Protocol
- libIEC61850: [https://github.com/mzillgith/libIEC61850](https://github.com/mzillgith/libIEC61850)
- IEC 61850: Communication networks and systems for power utility automation

