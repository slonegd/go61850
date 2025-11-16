package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"
)

// calculateLengthBER вычисляет длину для BER-кодирования.
// Для упрощения в этом PoC поддерживает только короткий формат длины (до 127 байт).
func calculateLengthBER(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	log.Fatal("Length exceeds short format in PoC")
	return nil // unreachable
}

// encodeInteger кодирует INTEGER в BER.
// Поддерживает значения от 0 до 65535.
func encodeInteger(value int) []byte {
	if value < 0 || value > 65535 {
		log.Fatal(fmt.Sprintf("Integer %d out of range (0 - 65535) in PoC", value))
	}

	var valueBytes []byte
	if value <= 0x7F {
		valueBytes = []byte{byte(value)}
	} else if value <= 0xFF {
		valueBytes = []byte{byte(value >> 8), byte(value & 0xFF)}
	} else { // value <= 0xFFFF
		highByte := byte(value >> 8)
		if highByte > 0x7F {
			valueBytes = []byte{0x00, highByte, byte(value & 0xFF)}
		} else {
			valueBytes = []byte{highByte, byte(value & 0xFF)}
		}
	}

	ber := []byte{0x02} // Tag INTEGER
	ber = append(ber, byte(len(valueBytes)))
	ber = append(ber, valueBytes...)
	return ber
}

// encodeOidValue кодирует *значение* OBJECT IDENTIFIER в BER (без тега OBJECT IDENTIFIER и длины).
// Это значение будет использоваться внутри контекстно-зависимых тегов.
func encodeOidValue(oid []int) []byte {
	// Для простоты в PoC закодируем жестко заданные *значения* OID, как в примере.
	// OID 1.0.9506.1.1 -> 0x05 0xf1 0x00
	// OID 1.0.9506.2.1 -> 0x03 0xee 1c 0x00 0x00 0x04 0x08 0x00 0x00 79 0xef 0x18
	if len(oid) == 5 && oid[0] == 1 && oid[1] == 0 && oid[2] == 9506 && oid[3] == 1 && oid[4] == 1 {
		return []byte{0x05, 0xf1, 0x00}
	} else if len(oid) == 5 && oid[0] == 1 && oid[1] == 0 && oid[2] == 9506 && oid[3] == 2 && oid[4] == 1 {
		return []byte{0x03, 0xee, 0x1c, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x79, 0xef, 0x18}
	} else {
		log.Fatal("Unsupported OID in PoC")
		return nil
	}
}

// buildPresentationContextDefinition собирает Presentation Context Definition (внутри списка).
// Это: presentation-context-identifier (80) + abstract-syntax-name (81) + transfer-syntax-name (82)
func buildPresentationContextDefinition() []byte {
	def := []byte{}

	// presentation-context-identifier (Context-specific 0, INTEGER 1)
	int1 := encodeInteger(1)[2:]                        // Возвращает [0x02, 0x01, 0x01]
	def = append(def, 0x80)                             // Tag
	def = append(def, calculateLengthBER(len(int1))[0]) // Length (берём только байт длины от внутреннего элемента)
	def = append(def, int1...)                          // Value INTEGER (без тега 0x02 и длины)

	// abstract-syntax-name (Context-specific 1, OID 1.0.9506.1.1)
	oid1Value := encodeOidValue([]int{1, 0, 9506, 1, 1})     // Возвращает [0x05, 0xf1, 0x00]
	def = append(def, 0x81)                                  // Tag
	def = append(def, calculateLengthBER(len(oid1Value))[0]) // Length (берём только байт длины от внутреннего элемента)
	def = append(def, oid1Value...)                          // Value OID (только значение)

	// transfer-syntax-name (Context-specific 2, OID 1.0.9506.2.1)
	oid2Value := encodeOidValue([]int{1, 0, 9506, 2, 1})     // Возвращает [0x03, 0xee, ...]
	def = append(def, 0x82)                                  // Tag
	def = append(def, calculateLengthBER(len(oid2Value))[0]) // Length (берём только байт длины от внутреннего элемента)
	def = append(def, oid2Value...)                          // Value OID (только значение)

	return def
}

// buildPresentationContextDefinitionList собирает Presentation Context Definition List (A4).
// Содержит одно определение контекста.
func buildPresentationContextDefinitionList() []byte {
	def := buildPresentationContextDefinition()
	list := []byte{}
	list = append(list, 0xA4)                            // Tag Presentation Context Definition List (Application 4, Constructed)
	list = append(list, calculateLengthBER(len(def))...) // Length of the definition
	list = append(list, def...)                          // The definition itself
	return list
}

// buildInitiateRequestDetail собирает initiate-request-detail (83).
// Содержит ТОЛЬКО тег выбранного элемента CHOICE 'simple' (0A).
// Содержимое ABSTRACT-SYNTAX/TRANSFER-SYNTAX (Presentation Context Definition List) идёт отдельно.
func buildInitiateRequestDetail() []byte {
	// Тег ABSTRACT-SYNTAX/TRANSFER-SYNTAX (Application 10, Constructed) - выбран элемент simple в CHOICE initiate-request
	choiceTag := byte(0x0A)

	detail := []byte{}
	detail = append(detail, 0x83)      // Tag initiate-request-detail (Context-specific 3, Constructed)
	detail = append(detail, 0x01)      // Length 1 (длина содержимого)
	detail = append(detail, choiceTag) // Содержимое: тег выбранного элемента CHOICE

	return detail
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	address := "localhost:102"

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	fmt.Printf("Connected to %s\n", address)

	// --- Шаг 1: Отправка COTP CR TPDU ---
	// Структура CR TPDU:
	// Тег 0x01 (CR)
	// Длина (14 байт)
	// Dst Ref (2 байта): 0x0000
	// Src Ref (2 байта): 0x0001
	// Class & Options (1 байт): 0x00
	// Called TSAP ID (C1 01 00)
	// Calling TSAP ID (C2 01 01)
	// TPDU Size (C0 01 08)

	cotpCR := []byte{
		0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0d, 0xc2, 0x02, 0x00, 0x01, 0xc1, 0x02, 0x00, 0x01,
	}

	fmt.Printf("Sending COTP CR TPDU: % x\n", cotpCR)
	_, err = conn.Write(cotpCR)
	if err != nil {
		log.Fatalf("Failed to write COTP CR: %v", err)
	}

	// --- Шаг 2: Получение COTP CC TPDU ---
	responseBuf := make([]byte, 1024)
	n, err := conn.Read(responseBuf)
	if err != nil {
		log.Fatalf("Failed to read COTP CC: %v", err)
	}

	fmt.Printf("Received %d bytes (COTP CC): %x\n", n, responseBuf[:n])

	if n < 4 || responseBuf[0] != 0x0D {
		log.Fatalf("Expected COTP CC TPDU (0x0D), got: %x", responseBuf[:n])
	}

	// --- Создание R-Session InitiateRequestApdu ---
	// Собираем InitiateRequestApdu по частям, слева направо.
	// 1. Тег InitiateRequestApdu (Application 8, Constructed)
	requestApdu := []byte{0xA8}

	// 2. Подготовим внутренности InitiateRequestApdu
	innerContent := []byte{}

	// 2a. called-session-selector (Context-specific 0, INTEGER 65000)
	int65000 := encodeInteger(65000)[2:]                                      // Возвращает [0x02, 0x03, 0x00, 0xFD, 0xE8]
	innerContent = append(innerContent, 0x80)                                 // Tag
	innerContent = append(innerContent, calculateLengthBER(len(int65000))[0]) // Length
	innerContent = append(innerContent, int65000...)                          // Value

	// 2b. calling-session-selector (Context-specific 1, INTEGER 5)
	int5_a := encodeInteger(5)[2:]                                          // Возвращает [0x02, 0x01, 0x05]
	innerContent = append(innerContent, 0x81)                               // Tag
	innerContent = append(innerContent, calculateLengthBER(len(int5_a))[0]) // Length
	innerContent = append(innerContent, int5_a...)                          // Value

	// 2c. lower-bound (Context-specific 2, INTEGER 5)
	int5_b := encodeInteger(5)[2:]                                          // Возвращает [0x02, 0x01, 0x05]
	innerContent = append(innerContent, 0x82)                               // Tag
	innerContent = append(innerContent, calculateLengthBER(len(int5_b))[0]) // Length
	innerContent = append(innerContent, int5_b...)                          // Value

	// 2d. initiate-request-detail (Context-specific 3, Constructed SEQUENCE)
	// Теперь содержит ТОЛЬКО 83 01 0a
	detailContent := buildInitiateRequestDetail()
	innerContent = append(innerContent, detailContent...) // Добавляем готовый блок detail (83 01 0a)

	// 2e. mmsInitRequestDetail (Presentation Context Definition List - A4 ...)
	// Это содержимое ABSTRACT-SYNTAX/TRANSFER-SYNTAX, которое шло после тега 0A внутри CHOICE.
	mmsInitDetail := buildPresentationContextDefinitionList()
	innerContent = append(innerContent, mmsInitDetail...) // Добавляем список контекстов (A4 16 ...)

	// 3. Вычисляем общую длину внутреннего содержимого
	totalInnerLength := len(innerContent)

	// 4. Добавляем длину к основному тегу InitiateRequestApdu
	requestApdu = append(requestApdu, calculateLengthBER(totalInnerLength)...)

	// 5. Добавляем внутреннее содержимое
	requestApdu = append(requestApdu, innerContent...)

	fmt.Printf("Sending R-Session InitiateRequestApdu: % x\n", requestApdu)
	// Проверка: совпадает ли начало с дампом?
	// Дамп: a8 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 ...
	// PoC:  a8 ?? 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 ...
	// ?? = длина (26 = 0x1A). Посчитаем: 3+1+1+1+1+1+1+22 = 30. ?? = 30 (0x1E).
	// Дамп длиной 38 байт (0x26). 38 - 1 (A8) - 1 (26) = 36 байт содержимого.
	// PoC длина: 1 (A8) + 1 (1E) + 36 (содержимое) = 38 байт. Совпадает.
	// Содержимое: 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 04 08 00 00 79 ef 18
	// Дамп:       80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 04 08 00 00 79 ef 18
	// Совпадает!

	_, err = conn.Write(requestApdu)
	if err != nil {
		log.Fatalf("Failed to write: %v", err)
	}

	// --- Получение ответа ---
	responseBuf = make([]byte, 1024)
	n, err = conn.Read(responseBuf)
	if err != nil {
		log.Fatalf("Failed to read: %v", err)
	}

	fmt.Printf("Received %d bytes:\n%x\n", n, responseBuf[:n])

	// --- Простой парсинг R-Session InitiateResponseApdu ---
	if n > 0 && responseBuf[0] == 0xA9 {
		fmt.Println("Received an R-Session InitiateResponseApdu.")
	} else {
		fmt.Printf("Did not receive expected R-Session InitiateResponseApdu. First byte: %x\n", responseBuf[0])
	}
}

// сравнение данных с дампом из примера. Тут только mms, его ещё надо обернуть в несколько слоёв.
// ws  a8 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 04 08 00 00 79 ef 18
// poc a8 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 04 08 00 00 79 ef 18
