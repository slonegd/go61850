# BER Package

Пакет `ber` предоставляет реализацию кодировщика и декодировщика Basic Encoding Rules (BER) для ASN.1, основанную на библиотеке libIEC61850. Этот пакет используется в стеке протоколов IEC 61850 для кодирования и декодирования данных в формате BER.

## Описание

BER (Basic Encoding Rules) — это один из стандартов кодирования данных ASN.1, используемый для сериализации структурированных данных. Пакет `ber` реализует функции для работы с BER-кодированными данными, включая:

- Декодирование и кодирование длин (включая неопределённую длину)
- Декодирование и кодирование примитивных типов (строки, целые числа, булевы значения, числа с плавающей точкой)
- Работа с Object Identifier (OID)
- Кодирование и декодирование битовых строк и октетных строк

## Основные типы

### ItuObjectIdentifier

Представляет ITU-T Object Identifier (OID):

```go
type ItuObjectIdentifier struct {
    Arc      [10]uint32
    ArcCount int
}
```

### Asn1PrimitiveValue

Представляет примитивное значение ASN.1:

```go
type Asn1PrimitiveValue struct {
    Size    uint8
    MaxSize uint8
    Octets  []byte
}
```

## Функции декодирования

### DecodeLength

Декодирует поле длины BER из буфера:

```go
newPos, length, err := DecodeLength(buffer, bufPos, maxBufPos)
```

Возвращает новую позицию в буфере, декодированную длину или ошибку.

### DecodeString

Декодирует строку BER из буфера:

```go
str, err := DecodeString(buffer, strlen, bufPos, maxBufPos)
```

### DecodeUint32 / DecodeInt32

Декодируют беззнаковое и знаковое 32-битное целое число:

```go
value := DecodeUint32(buffer, intLen, bufPos)
value := DecodeInt32(buffer, intLen, bufPos)
```

### DecodeFloat / DecodeDouble

Декодируют числа с плавающей точкой:

```go
value := DecodeFloat(buffer, bufPos)
value := DecodeDouble(buffer, bufPos)
```

### DecodeBoolean

Декодирует булево значение:

```go
value := DecodeBoolean(buffer, bufPos)
```

### DecodeOID

Декодирует Object Identifier:

```go
var oid ItuObjectIdentifier
DecodeOID(buffer, bufPos, length, &oid)
```

## Функции кодирования

### EncodeLength

Кодирует значение длины в формате BER:

```go
newPos := EncodeLength(length, buffer, bufPos)
```

### EncodeTL

Кодирует тег и длину в формате BER:

```go
newPos := EncodeTL(tag, length, buffer, bufPos)
```

### EncodeBoolean

Кодирует булево значение с тегом:

```go
newPos := EncodeBoolean(tag, value, buffer, bufPos)
```

### EncodeStringWithTag

Кодирует строку с тегом:

```go
newPos := EncodeStringWithTag(tag, str, buffer, bufPos)
```

### EncodeOctetString

Кодирует октетную строку с тегом:

```go
newPos := EncodeOctetString(tag, octetString, buffer, bufPos)
```

### EncodeUInt32 / EncodeInt32

Кодируют целые числа:

```go
newPos := EncodeUInt32(value, buffer, bufPos)
newPos := EncodeInt32(value, buffer, bufPos)
```

### EncodeUInt32WithTL

Кодирует беззнаковое 32-битное целое число с тегом и длиной:

```go
newPos := EncodeUInt32WithTL(tag, value, buffer, bufPos)
```

### EncodeBitString

Кодирует битовую строку с тегом:

```go
newPos := EncodeBitString(tag, bitStringSize, bitString, buffer, bufPos)
```

### EncodeOIDToBuffer

Кодирует строку OID в буфер:

```go
bytes, err := EncodeOIDToBuffer("1.0.9506.2.1", buffer, maxBufLen)
```

## Вспомогательные функции

### CompressInteger

Удаляет ведущие нулевые байты или ведущие байты 0xFF из целого числа:

```go
newSize := CompressInteger(integer)
```

### RevertByteOrder

Обращает порядок байтов в срезе:

```go
RevertByteOrder(octets)
```

### Функции определения размера

- `DetermineLengthSize(length uint32) int` — определяет размер, необходимый для кодирования значения длины
- `DetermineEncodedStringSize(str string) int` — определяет закодированный размер строки
- `DetermineEncodedBitStringSize(bitStringSize int) int` — определяет закодированный размер битовой строки
- `UInt32DetermineEncodedSize(value uint32) int` — определяет закодированный размер беззнакового 32-битного целого числа
- `Int32DetermineEncodedSize(value int32) int` — определяет закодированный размер знакового 32-битного целого числа

## Ошибки

Пакет определяет следующие ошибки:

- `ErrBufferOverflow` — переполнение буфера
- `ErrInvalidLength` — недопустимая длина
- `ErrInvalidIndefinite` — недопустимая неопределённая длина
- `ErrMaxDepthExceeded` — превышена максимальная глубина рекурсии

## Примеры использования

### Декодирование длины

```go
buffer := []byte{0x81, 0xFF}
pos, length, err := DecodeLength(buffer, 0, len(buffer))
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Length: %d, New position: %d\n", length, pos)
```

### Кодирование целого числа

```go
buffer := make([]byte, 10)
value := uint32(0x12345678)
pos := EncodeUInt32(value, buffer, 0)
fmt.Printf("Encoded %d bytes\n", pos)
```

### Работа с OID

```go
// Декодирование OID
buffer := []byte{0x28, 0xca, 0x22, 0x02, 0x01}
var oid ItuObjectIdentifier
DecodeOID(buffer, 0, 5, &oid)
fmt.Printf("OID arcs: %v\n", oid.Arc[:oid.ArcCount])

// Кодирование OID
encodeBuffer := make([]byte, 20)
bytes, err := EncodeOIDToBuffer("1.0.9506.2.1", encodeBuffer, 20)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Encoded %d bytes\n", bytes)
```

### Кодирование строки с тегом

```go
buffer := make([]byte, 20)
tag := byte(0x0C) // UTF8String tag
str := "Hello, World!"
pos := EncodeStringWithTag(tag, str, buffer, 0)
fmt.Printf("Encoded %d bytes\n", pos)
```

## Тестирование

Пакет включает комплексные табличные тесты для всех функций кодирования и декодирования. Запустите тесты командой:

```bash
go test ./ber
```

Тесты включают:
- Тесты для всех функций декодирования
- Тесты для всех функций кодирования
- Тесты round-trip (кодирование и последующее декодирование)
- Тесты обработки ошибок
- Тесты граничных случаев

## Основано на

Этот пакет основан на исходном коде библиотеки [libIEC61850](https://github.com/mz-automation/libiec61850) от Michael Zillgith, которая распространяется под лицензией GNU General Public License версии 3 или более поздней.

## Лицензия

См. файл LICENSE в корне проекта.

