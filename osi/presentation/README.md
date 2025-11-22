# Presentation Package

Пакет `presentation` реализует протокол ISO 8823 OSI Presentation Protocol, используемый в IEC 61850 для определения синтаксиса обмена данными между приложениями. Реализация основана на библиотеке `libIEC61850` (C).

## Основные концепции

### CP-type - Connect Presentation PDU
Клиент отправляет CP-type для инициализации представления. Сообщение содержит:
- Mode-selector (режим работы, например, normal-mode)
- Normal-mode-parameters (параметры нормального режима):
  - Calling Presentation Selector (селектор вызывающей стороны)
  - Called Presentation Selector (селектор вызываемой стороны)
  - Presentation Context Definition List (список определений контекстов представления)
  - User Data (данные пользователя для вышестоящих уровней)

### Структура Presentation
Внутренняя структура `Presentation` хранит состояние представления:
- `callingPresentationSelector` - селектор вызывающей стороны
- `calledPresentationSelector` - селектор вызываемой стороны
- `acseContextId` - идентификатор контекста ACSE (по умолчанию 1)
- `mmsContextId` - идентификатор контекста MMS (по умолчанию 3)

## Быстрый старт

### Создание CP-type PDU

```go
package main

import (
    "github.com/slonegd/go61850/osi/presentation"
)

func main() {
    // Данные от вышестоящих уровней (например, ACSE PDU)
    acseData := []byte{0x60, 0x55, /* ... */}

    // Создание CP-type PDU с параметрами по умолчанию
    cpType := presentation.BuildCPType(acseData)

    // Отправка через Session соединение
    // (см. примеры в пакете session)
}
```

### Использование с кастомными параметрами

```go
package main

import (
    "github.com/slonegd/go61850/osi/presentation"
)

func main() {
    // Создание представления с параметрами по умолчанию
    pres := presentation.NewPresentation()
    
    // Параметры по умолчанию:
    // - acseContextId = 1
    // - mmsContextId = 3
    // - callingPresentationSelector = [0, 0, 0, 1]
    // - calledPresentationSelector = [0, 0, 0, 1]

    // Данные от вышестоящих уровней
    userData := []byte{/* ... */}

    // Использование внутренней функции для создания PDU
    // (в текущей реализации BuildCPType использует NewPresentation() внутри)
    cpType := presentation.BuildCPType(userData)
}
```

## API Reference

### Типы

#### `PSelector`
Селектор представления, используемый для идентификации представления.

```go
type PSelector struct {
    Value []byte
}
```

#### `Presentation`
Внутренняя структура, представляющая состояние представления ISO 8823.

```go
type Presentation struct {
    callingPresentationSelector PSelector
    calledPresentationSelector  PSelector
    acseContextId               uint8
    mmsContextId                uint8
    nextContextId              uint8
}
```

### Функции

#### `NewPresentation() *Presentation`
Создаёт новое представление с параметрами по умолчанию:
- `acseContextId = 1`
- `mmsContextId = 3`
- `callingPresentationSelector = [0, 0, 0, 1]`
- `calledPresentationSelector = [0, 0, 0, 1]`

Эти значения соответствуют функции `IsoPresentation_createConnectPdu` из C библиотеки `libIEC61850`.

#### `BuildCPType(userData []byte) []byte`
Создаёт CP-type (Connect Presentation) PDU для установления представления.

**Параметры:**
- `userData` - данные от вышестоящих уровней (например, ACSE PDU)

**Возвращает:**
- Байтовый массив, содержащий полностью сформированный CP-type PDU

**Реализация:**
Функция основана на `IsoPresentation_createConnectPdu` из C библиотеки (строки 892-901 в `iso_presentation.c`). Использует значения по умолчанию, соответствующие `createConnectPdu`.

**Структура создаваемого PDU:**
1. CP-type: `0x31` (Application 1, Constructed)
2. Length: вычисляется автоматически
3. Mode-selector: `0xA0` (Context-specific 0, Constructed)
   - Mode-value: `0x80 0x01 0x01` (normal-mode = 1)
4. Normal-mode-parameters: `0xA2` (Context-specific 2, Constructed)
   - Calling Presentation Selector: `0x81` + длина + значение
   - Called Presentation Selector: `0x82` + длина + значение
   - Presentation Context Definition List: `0xA4` + список контекстов
     - ACSE context (context-id = 1)
     - MMS context (context-id = 3)
   - User Data: `0x61` (fully-encoded-data)
     - PDV-list: `0x30` (SEQUENCE)
       - Presentation-context-identifier: `0x02` (INTEGER)
       - Presentation-data-values: `0xA0` (Context-specific 0, Constructed)
         - User Data: содержимое `userData`

## Внутренние функции кодирования

Пакет содержит приватные функции кодирования, соответствующие функциям из C библиотеки:

- `encodeTL` - кодирует тег и длину в BER формат (соответствует `BerEncoder_encodeTL`)
- `determineLengthSize` - определяет размер поля длины в BER кодировании (соответствует `BerEncoder_determineLengthSize`)
- `encodeUserData` - кодирует user data (строки 59-97 в `iso_presentation.c`)
- `createConnectPdu` - создаёт CP-type PDU (строки 99-189)

## Интеграция с другими уровнями OSI

Presentation уровень находится между ACSE и Session уровнями:

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

### Кодирование BER
Реализация использует низкоуровневое BER кодирование, соответствующее C библиотеке:
- Функция `encodeTL` кодирует тег и длину в BER формат
- Поддерживается короткий формат длины (до 127 байт) и длинный формат (для больших значений)
- Кодирование соответствует спецификации ISO 8823

### Соответствие C библиотеке
Реализация следует логике библиотеки `libIEC61850`:
- Структура `Presentation` соответствует `IsoPresentation` из `iso_presentation.h`
- Функции кодирования соответствуют функциям из `iso_presentation.c`
- Значения по умолчанию соответствуют `IsoPresentation_createConnectPdu`

### Контексты представления
Пакет поддерживает два контекста представления:
- **ACSE context** (context-id = 1): для Association Control Service Element
- **MMS context** (context-id = 3): для Manufacturing Message Specification

Оба контекста используют basic-encoding (BER) как transfer-syntax-name.

## Примечания

- Пакет реализует только создание CP-type PDU (клиентская сторона)
- Парсинг входящих PDU и создание других типов PDU (CPA, CPABORT) могут быть добавлены в будущем
- Все значения по умолчанию соответствуют стандартным настройкам для IEC 61850
- Библиотека `github.com/go-asn1-ber/asn1-ber` добавлена в зависимости, но в текущей реализации используется низкоуровневое кодирование для точного соответствия C библиотеке

## Ссылки

- ISO 8823: OSI Presentation Protocol
- libIEC61850: [https://github.com/mzillgith/libIEC61850](https://github.com/mzillgith/libIEC61850)
- IEC 61850: Communication networks and systems for power utility automation

