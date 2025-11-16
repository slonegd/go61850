Хорошо, давайте начнём с простого Proof of Concept (PoC) и составим итеративный TODO-список для дальнейшего развития библиотеки.

**Proof of Concept (PoC): TCP-соединение и InitiateRequest MMS**

Цель: Установить TCP-соединение с IED (или симулятором), отправить базовый MMS `InitiateRequest`, получить `InitiateResponse` и распечатать его (или хотя бы его длину/части).

**Шаги:**

1.  **Создайте Go-модуль:**
    ```bash
    mkdir iec61850-go-poc
    cd iec61850-go-poc
    go mod init iec61850-go-poc
    ```
2.  **Напишите `main.go`:**
    *   Используйте `net.Dial` для подключения к IED (например, `localhost:102` или реальный IP).
    *   Используйте `context.WithTimeout` для управления таймаутом соединения и обмена.
    *   Создайте *очень* упрощённый байтовый массив, представляющий `InitiateRequestPdu` в ASN.1 BER. Это можно сделать "вручную", используя `[]byte`, пока не будет реализован полноценный парсер. Пример структуры `InitiateRequestPdu` (упрощённый):
        *   Тег `C1` (Constructed, Application 1 - ConfirmedRequestPDU)
        *   Длина (длина остальных данных)
        *   Invoke ID (например, `02 01 01` - INTEGER 1)
        *   Service (например, `02 01 06` - INTEGER 6 - GetNameList, но для InitiateRequest это будет Application 0)
        *   *Правильный* `InitiateRequest` сложнее, но можно использовать минимальный, просто чтобы получить ответ.
        *   Правильный `InitiateRequest` (Application 0):
            *   Тег `60` (Application 0)
            *   Длина
            *   `local-detail-calling` (INTEGER, например `02 01 01`)
            *   `max-apdu-length-accepted` (INTEGER, например `02 01 65` - 101 bytes)
            *   `negotiated-quality` (обычно опускается или `07 00` - NULL для октет-строки, но нужен `parameters-accepted`!)
            *   `maxServOutstandingCalling` (INTEGER, `02 01 05`)
            *   `maxServOutstandingCalled` (INTEGER, `02 01 05`)
            *   `dataStructureNestingLevel` (INTEGER, `02 01 10` - 16)
            *   `initiateResponseTimeout` (INTEGER, `02 01 0F` - 15 секунд)
        *   Пример минимального `InitiateRequestPdu` (BER Encoded):
            *   `C1` (Тег ConfirmedRequestPDU)
            *   `17` (Длина: 23 байта)
            *   `02 01 01` (Invoke ID: INTEGER 1)
            *   `60 0E` (Тег InitiateRequest, длина 14)
            *   `02 01 01` (local-detail-calling)
            *   `02 01 65` (max-apdu-length-accepted - 101)
            *   `02 01 05` (maxServOutstandingCalling)
            *   `02 01 05` (maxServOutstandingCalled)
            *   `02 01 10` (dataStructureNestingLevel)
            *   `02 01 0F` (initiateResponseTimeout)
        *   Байты: `[]byte{0xC1, 0x17, 0x02, 0x01, 0x01, 0x60, 0x0E, 0x02, 0x01, 0x01, 0x02, 0x01, 0x65, 0x02, 0x01, 0x05, 0x02, 0x01, 0x05, 0x02, 0x01, 0x10, 0x02, 0x01, 0x0F}`
    *   Запишите этот массив байтов в соединение.
    *   Прочитайте ответные байты.
    *   Распечатайте полученные байты или их длину.

**`main.go` (Пример PoC):**

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Замените на IP/hostname и порт вашего IED или симулятора
	address := "localhost:102"

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	fmt.Printf("Connected to %s\n", address)

	// --- PoC: Отправка InitiateRequest ---
	// BER-кодированный MMS InitiateRequest PDU (упрощённый/минимальный)
	// См. комментарий выше для структуры
	initiateRequestPdu := []byte{
		0xC1, 0x17, // ConfirmedRequestPDU (Tag C1, Length 23)
		0x02, 0x01, 0x01, // invokeID (INTEGER 1)
		0x60, 0x0E, // InitiateRequest (Application 0, Length 14)
		0x02, 0x01, 0x01, // local-detail-calling (INTEGER 1)
		0x02, 0x01, 0x65, // max-apdu-length-accepted (INTEGER 101)
		0x02, 0x01, 0x05, // maxServOutstandingCalling (INTEGER 5)
		0x02, 0x01, 0x05, // maxServOutstandingCalled (INTEGER 5)
		0x02, 0x01, 0x10, // dataStructureNestingLevel (INTEGER 16)
		0x02, 0x01, 0x0F, // initiateResponseTimeout (INTEGER 15)
	}

	fmt.Printf("Sending InitiateRequest: %x\n", initiateRequestPdu)
	_, err = conn.Write(initiateRequestPdu)
	if err != nil {
		log.Fatalf("Failed to write: %v", err)
	}

	// --- PoC: Получение ответа ---
	// Буфер для получения ответа (для PoC используем фиксированный размер)
	responseBuf := make([]byte, 1024)
	n, err := conn.Read(responseBuf)
	if err != nil {
		log.Fatalf("Failed to read: %v", err)
	}

	fmt.Printf("Received %d bytes:\n%x\n", n, responseBuf[:n])

	// --- PoC: Простой парсинг InitiateResponse ---
	// Проверим, начинается ли ответ с тега ConfirmedResponsePDU (C2)
	// Это грубая проверка, но подходит для PoC
	if n > 0 && responseBuf[0] == 0xC2 {
		fmt.Println("Received a ConfirmedResponsePDU (likely InitiateResponse).")
		// В реальности нужно будет парсить длину и т.д.
	} else {
		fmt.Println("Did not receive expected ConfirmedResponsePDU.")
	}
}
```

**Запуск PoC:**

*   Убедитесь, что у вас запущен IED или симулятор IEC 61850, слушающий на порту 102 (например, `61850_client_server_example` из `libiec61850`).
*   Запустите `go run main.go`.

Если всё работает, вы должны увидеть подключение, отправку байтов и получение ответа от IED/симулятора.

---

**TODO List для дальнейшего усложнения (итеративно):**

**Итерация 1: Улучшенный PoC и парсинг BER**

1.  [x] Создать Go-модуль.
2.  [x] Написать PoC `main.go` с `net.Dial`, `context`, `Write`, `Read`.
3.  [x] Отправить простой `InitiateRequest` (вручную закодированный).
4.  [x] Получить и распечатать `InitiateResponse`.
5.  [ ] **(Новый)** Подключить библиотеку `github.com/google/go-asn1-ber` (`go get github.com/google/go-asn1-ber`).
6.  [ ] **(Новый)** Использовать `asn1-ber` для *разбора* полученного `InitiateResponse`. Проверить его структуру (Invoke ID, Service Type, Parameters).
7.  [ ] **(Новый)** Попробовать отправить *правильный* `InitiateRequest`, используя `asn1-ber` для *создания* PDU, а не вручную закодированный массив.

**Итерация 2: Базовая структура библиотеки и MMS PDU**

1.  [ ] Создать пакет `mms` (например, `iec61850-go-poc/mms`).
2.  [ ] Создать структуры Go для `ConfirmedRequestPdu`, `ConfirmedResponsePdu`, `InitiateRequest`, `InitiateResponse`.
3.  [ ] Реализовать методы `Marshal()` (для отправки) и `Unmarshal(data []byte)` (для получения) для этих структур, используя `asn1-ber`.
4.  [ ] Вынести логику соединения в отдельную структуру `Connection` в новом пакете (например, `iec61850-go-poc/conn`).
5.  [ ] Интегрировать структуры `mms` и `conn` в `main.go`.

**Итерация 3: Базовый MMS клиент**

1.  [ ] Создать пакет `mmsclient`.
2.  [ ] Создать структуру `MmsClient`, которая использует `conn.Connection`.
3.  [ ] Реализовать метод `Connect(ctx, address)` в `MmsClient`, который:
    *   Создаёт соединение.
    *   Отправляет `InitiateRequest`.
    *   Получает и проверяет `InitiateResponse`.
4.  [ ] Обработать ошибки и таймауты через `context`.

**Итерация 4: IEC 61850 модели и адресации**

1.  [ ] Создать пакет `model` или `iedmodel`.
2.  [ ] Создать структуры для `LogicalDevice`, `LogicalNode`, `DataObject`, `DataAttribute`.
3.  [ ] Создать тип `ObjectReference` (например, `string` или `struct {LD, LN, DO, DA, FC string}`).
4.  [ ] Реализовать функции для преобразования `ObjectReference` в MMS `ObjectReference` (OID в ASN.1).

**Итерация 5: Базовый IEC 61850 клиент**

1.  [ ] Создать пакет `client`.
2.  [ ] Создать структуру `IedClient`, которая использует `mmsclient.MmsClient`.
3.  [ ] Реализовать метод `Connect(ctx, address)` в `IedClient`.
4.  [ ] Реализовать метод `GetNameList(ctx, domainSpecific, objectScope, name)` для получения списка LD/LN/DO/DA.
5.  [ ] Реализовать метод `GetDataValues(ctx, objectReferences)` для чтения значений.

**Итерация 6: Улучшения API и функциональности**

1.  [ ] Реализовать `SetDataValues`.
2.  [ ] Реализовать `SubscribeReports` (отчеты).
3.  [ ] Реализовать `CreateDataSet`, `GetDataSetValues`, `SetDataSetValues`.
4.  [ ] Добавить опции конфигурации (functional options).
5.  [ ] Добавить полноценную документацию (`godoc`).
6.  [ ] Написать базовые модульные тесты.

... и так далее, вплоть до TLS, GOOSE, SV, если потребуется.

Этот PoC и TODO-список дают вам чёткую отправную точку и направление. Удачи!