package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/slonegd/go61850/cotp"
)

// ExampleClient демонстрирует использование COTP для клиентской стороны:
// отправка Connection Request (CR) и обработка Connection Confirm (CC).
func ExampleClient() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Создание клиента
	client := NewClient("localhost:102", nil)

	// Настройка параметров соединения
	params := &cotp.IsoConnectionParameters{
		RemoteTSelector: cotp.TSelector{Value: []byte{0, 1}}, // TSAP сервера
		LocalTSelector:  cotp.TSelector{Value: []byte{0, 1}}, // TSAP клиента
	}

	// Подключение
	if err := client.Connect(ctx, params); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	fmt.Println("Connection established")
}

// ExampleServer демонстрирует использование COTP для серверной стороны:
// обработка Connection Request (CR) и отправка Connection Confirm (CC).
func ExampleServer() {
	// Создание сервера
	server := NewServer(":102")

	// Установка обработчика
	server.SetHandler(func(conn *Connection) error {
		fmt.Printf("Connection established (remote ref: %d, local ref: %d)\n",
			conn.GetConnection().GetRemoteRef(),
			conn.GetConnection().GetLocalRef())
		return nil
	})

	// Запуск сервера
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	fmt.Println("Server listening on :102")
	select {} // Бесконечное ожидание
}

// ExampleDataExchange демонстрирует обмен данными после установления соединения.
func ExampleDataExchange() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Создание клиента
	client := NewClient("localhost:102", nil)

	// Настройка параметров
	params := &cotp.IsoConnectionParameters{
		RemoteTSelector: cotp.TSelector{Value: []byte{0, 1}},
		LocalTSelector:  cotp.TSelector{Value: []byte{0, 1}},
	}

	// Подключение
	if err := client.Connect(ctx, params); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Отправка данных
	payload := []byte{0x60, 0x1e, 0xa1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01}
	if err := client.SendData(payload); err != nil {
		log.Fatalf("Failed to send data: %v", err)
	}

	fmt.Printf("Sent %d bytes of data\n", len(payload))

	// Получение ответа
	response, err := client.ReceiveData(5 * time.Second)
	if err != nil {
		log.Fatalf("Failed to receive data: %v", err)
	}

	fmt.Printf("Received %d bytes of data: %x\n", len(response), response)
}

// ExampleDisconnect демонстрирует обработку разрыва соединения.
func ExampleDisconnect() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Создание клиента
	client := NewClient("localhost:102", nil)

	// Настройка параметров
	params := &cotp.IsoConnectionParameters{
		RemoteTSelector: cotp.TSelector{Value: []byte{0, 1}},
		LocalTSelector:  cotp.TSelector{Value: []byte{0, 1}},
	}

	// Подключение
	if err := client.Connect(ctx, params); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	fmt.Println("Connection established")

	// Закрытие соединения
	client.Close()
	fmt.Println("Connection closed")
}
