package main

import (
	"context"
	"testing"
	"time"

	"github.com/slonegd/go61850/osi/cotp"
)

func TestConnectionRequestAndConfirm(t *testing.T) {
	// Создание сервера
	server := NewServer("localhost:0")

	server.SetHandler(func(conn *Connection) error {
		// Сервер просто принимает соединение
		return nil
	})

	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	// Получение адреса сервера
	addr := server.Addr().String()

	// Создание клиента
	client := NewClient(addr, nil)

	// Параметры соединения
	params := &cotp.IsoConnectionParameters{
		RemoteTSelector: cotp.TSelector{Value: []byte{0, 1}},
		LocalTSelector:  cotp.TSelector{Value: []byte{0, 1}},
	}

	// Подключение
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, params); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Проверка, что соединение установлено
	cotpConn := client.GetConnection()
	if cotpConn == nil {
		t.Fatal("COTP connection is nil")
	}

	if cotpConn.GetRemoteRef() < 0 {
		t.Error("Remote reference should be set")
	}

	if cotpConn.GetLocalRef() < 0 {
		t.Error("Local reference should be set")
	}

	client.Close()
}

func TestDataExchange(t *testing.T) {
	// Создание сервера
	server := NewServer("localhost:0")

	var receivedData []byte
	server.SetHandler(func(conn *Connection) error {
		// Получение данных от клиента
		data, err := conn.ReceiveData(5 * time.Second)
		if err != nil {
			return err
		}
		receivedData = data

		// Отправка ответа
		response := []byte{0x61, 0x1e, 0xa1, 0x09}
		return conn.SendData(response)
	})

	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	// Получение адреса сервера
	addr := server.Addr().String()

	// Создание клиента
	client := NewClient(addr, nil)

	// Параметры соединения
	params := &cotp.IsoConnectionParameters{
		RemoteTSelector: cotp.TSelector{Value: []byte{0, 1}},
		LocalTSelector:  cotp.TSelector{Value: []byte{0, 1}},
	}

	// Подключение
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, params); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Отправка данных
	testData := []byte{0x60, 0x1e, 0xa1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01}
	if err := client.SendData(testData); err != nil {
		t.Fatalf("Failed to send data: %v", err)
	}

	// Небольшая задержка для обработки на сервере
	time.Sleep(100 * time.Millisecond)

	// Проверка полученных данных на сервере
	if len(receivedData) == 0 {
		t.Error("Server did not receive data")
	}

	if len(receivedData) != len(testData) {
		t.Errorf("Received data length mismatch: got %d, want %d", len(receivedData), len(testData))
	}

	// Получение ответа от сервера
	response, err := client.ReceiveData(5 * time.Second)
	if err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	if len(response) == 0 {
		t.Error("Did not receive response from server")
	}

	expectedResponse := []byte{0x61, 0x1e, 0xa1, 0x09}
	if len(response) != len(expectedResponse) {
		t.Errorf("Response length mismatch: got %d, want %d", len(response), len(expectedResponse))
	}
}

func TestLargeDataFragmentation(t *testing.T) {
	// Создание сервера
	server := NewServer("localhost:0")

	var receivedData []byte
	server.SetHandler(func(conn *Connection) error {
		// Получение больших данных от клиента
		data, err := conn.ReceiveData(10 * time.Second)
		if err != nil {
			return err
		}
		receivedData = data
		return nil
	})

	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	// Получение адреса сервера
	addr := server.Addr().String()

	// Создание клиента
	client := NewClient(addr, nil)

	// Параметры соединения
	params := &cotp.IsoConnectionParameters{
		RemoteTSelector: cotp.TSelector{Value: []byte{0, 1}},
		LocalTSelector:  cotp.TSelector{Value: []byte{0, 1}},
	}

	// Подключение
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, params); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Создание больших данных (больше размера TPDU, но не слишком больших для extension буфера)
	// Размер должен быть больше TPDU (8192), но общий размер фрагментированного сообщения
	// не должен превышать extension buffer (8192)
	largeData := make([]byte, 5000)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	// Отправка больших данных (должны быть фрагментированы)
	if err := client.SendData(largeData); err != nil {
		t.Fatalf("Failed to send large data: %v", err)
	}

	// Небольшая задержка для обработки на сервере
	time.Sleep(500 * time.Millisecond)

	// Проверка полученных данных на сервере
	if len(receivedData) != len(largeData) {
		t.Errorf("Received data length mismatch: got %d, want %d", len(receivedData), len(largeData))
	}

	// Проверка содержимого
	for i := range largeData {
		if receivedData[i] != largeData[i] {
			t.Errorf("Data mismatch at index %d: got %d, want %d", i, receivedData[i], largeData[i])
			break
		}
	}
}

func TestMultipleConnections(t *testing.T) {
	// Создание сервера
	server := NewServer("localhost:0")

	connectionCount := 0
	server.SetHandler(func(conn *Connection) error {
		connectionCount++
		return nil
	})

	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	// Получение адреса сервера
	addr := server.Addr().String()

	// Параметры соединения
	params := &cotp.IsoConnectionParameters{
		RemoteTSelector: cotp.TSelector{Value: []byte{0, 1}},
		LocalTSelector:  cotp.TSelector{Value: []byte{0, 1}},
	}

	// Создание нескольких клиентов
	numClients := 5
	clients := make([]*Client, numClients)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for i := 0; i < numClients; i++ {
		client := NewClient(addr, nil)
		if err := client.Connect(ctx, params); err != nil {
			t.Fatalf("Failed to connect client %d: %v", i, err)
		}
		clients[i] = client
	}

	// Небольшая задержка для обработки на сервере
	time.Sleep(500 * time.Millisecond)

	// Проверка количества соединений
	if connectionCount != numClients {
		t.Errorf("Expected %d connections, got %d", numClients, connectionCount)
	}

	// Закрытие всех клиентов
	for _, client := range clients {
		client.Close()
	}
}

func TestConnectionTimeout(t *testing.T) {
	// Создание клиента с несуществующим адресом
	client := NewClient("localhost:99999", nil)

	// Параметры соединения
	params := &cotp.IsoConnectionParameters{
		RemoteTSelector: cotp.TSelector{Value: []byte{0, 1}},
		LocalTSelector:  cotp.TSelector{Value: []byte{0, 1}},
	}

	// Попытка подключения с коротким таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := client.Connect(ctx, params)
	if err == nil {
		t.Error("Expected connection error, got nil")
		client.Close()
	}
}

func TestBidirectionalDataExchange(t *testing.T) {
	// Создание сервера
	server := NewServer("localhost:0")

	messageCount := 0
	server.SetHandler(func(conn *Connection) error {
		// Обработка нескольких сообщений
		for messageCount < 3 {
			// Получение данных от клиента
			data, err := conn.ReceiveData(5 * time.Second)
			if err != nil {
				return err
			}

			// Отправка ответа (эхо)
			if err := conn.SendData(data); err != nil {
				return err
			}
			messageCount++
		}
		return nil
	})

	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	// Получение адреса сервера
	addr := server.Addr().String()

	// Создание клиента
	client := NewClient(addr, nil)

	// Параметры соединения
	params := &cotp.IsoConnectionParameters{
		RemoteTSelector: cotp.TSelector{Value: []byte{0, 1}},
		LocalTSelector:  cotp.TSelector{Value: []byte{0, 1}},
	}

	// Подключение
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx, params); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Отправка нескольких сообщений
	messages := [][]byte{
		[]byte("Hello"),
		[]byte("World"),
		[]byte{0x01, 0x02, 0x03, 0x04},
	}

	for i, msg := range messages {
		// Отправка
		if err := client.SendData(msg); err != nil {
			t.Fatalf("Failed to send message %d: %v", i, err)
		}

		// Получение ответа
		response, err := client.ReceiveData(5 * time.Second)
		if err != nil {
			t.Fatalf("Failed to receive response %d: %v", i, err)
		}

		// Проверка эха
		if len(response) != len(msg) {
			t.Errorf("Response %d length mismatch: got %d, want %d", i, len(response), len(msg))
		}

		for j := range msg {
			if response[j] != msg[j] {
				t.Errorf("Response %d mismatch at index %d: got %d, want %d", i, j, response[j], msg[j])
				break
			}
		}
	}
}
