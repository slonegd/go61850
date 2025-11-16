# Examples Package

Пакет `examples` предоставляет готовые клиент и сервер для работы с COTP протоколом.

## Компоненты

### Client

`Client` представляет COTP клиента, который может:
- Устанавливать соединение с сервером (Connection Request)
- Отправлять данные
- Получать данные

**Пример использования:**

```go
import (
    "context"
    "github.com/slonegd/go61850/cotp"
    "github.com/slonegd/go61850/examples"
)

client := examples.NewClient("localhost:102")
params := &cotp.IsoConnectionParameters{
    RemoteTSelector: cotp.TSelector{Value: []byte{0, 1}},
    LocalTSelector:  cotp.TSelector{Value: []byte{0, 1}},
}

ctx := context.Background()
if err := client.Connect(ctx, params); err != nil {
    log.Fatal(err)
}
defer client.Close()

// Отправка данных
client.SendData([]byte{0x60, 0x1e})

// Получение данных
data, err := client.ReceiveData(5 * time.Second)
```

### Server

`Server` представляет COTP сервер, который может:
- Принимать входящие соединения
- Обрабатывать Connection Request
- Отправлять Connection Confirm
- Обрабатывать обмен данными через обработчик

**Пример использования:**

```go
import (
    "github.com/slonegd/go61850/examples"
)

server := examples.NewServer(":102")
server.SetHandler(func(conn *examples.Connection) error {
    // Получение данных
    data, err := conn.ReceiveData(5 * time.Second)
    if err != nil {
        return err
    }
    
    // Отправка ответа
    return conn.SendData(data)
})

if err := server.Start(); err != nil {
    log.Fatal(err)
}
defer server.Stop()
```

### Connection

`Connection` представляет соединение на сервере. Предоставляет методы:
- `SendData(data []byte) error` - отправка данных
- `ReceiveData(timeout time.Duration) ([]byte, error)` - получение данных
- `GetConnection() *cotp.Connection` - получение базового COTP соединения
- `Close() error` - закрытие соединения

## Примеры кода

См. файл `examples.go` для полных примеров:
- `ExampleClient` - использование клиента
- `ExampleServer` - использование сервера
- `ExampleDataExchange` - обмен данными
- `ExampleDisconnect` - обработка разрыва соединения

## Тесты

Юнит-тесты находятся в `examples_test.go`:
- `TestConnectionRequestAndConfirm` - тест установления соединения
- `TestDataExchange` - тест обмена данными
- `TestLargeDataFragmentation` - тест фрагментации больших сообщений
- `TestMultipleConnections` - тест множественных соединений
- `TestConnectionTimeout` - тест таймаута соединения
- `TestBidirectionalDataExchange` - тест двунаправленного обмена данными

Запуск тестов:

```bash
go test ./examples
```

