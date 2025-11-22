package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/slonegd/go61850/osi/cotp"
)

// AppLogger реализует интерфейс Logger - просто выводит сообщения
type AppLogger struct {
	prefix string
}

func NewAppLogger(prefix string) *AppLogger {
	return &AppLogger{prefix: prefix}
}

func (l *AppLogger) Debug(format string, v ...any) {
	log.Printf("[%s] %s", l.prefix, fmt.Sprintf(format, v...))
}

func main() {
	address := "localhost:10200"
	duration := 5 * time.Second

	log.Printf("Starting COTP ping-pong demo (duration: %v)", duration)

	// Создание логгеров
	serverLogger := NewAppLogger("SERVER")
	clientLogger := NewAppLogger("CLIENT")

	// Запуск сервера в горутине
	server := NewServer(address)
	server.SetLogger(serverLogger)
	server.SetHandler(func(conn *Connection) error {
		serverLogger.Debug("New client connected")

		// Обработка сообщений до закрытия соединения
		for {
			// Получение ping с таймаутом
			data, err := conn.ReceiveData(2 * time.Second)
			if err != nil {
				serverLogger.Debug("Connection closed or timeout: %v", err)
				return nil
			}

			// Проверка типа сообщения
			msgStr := string(data)
			if msgStr == "ping" {
				serverLogger.Debug("Received PING message")

				// Отправка pong ответа
				if err := conn.SendData([]byte("pong")); err != nil {
					serverLogger.Debug("Failed to send pong: %v", err)
					return err
				}

				serverLogger.Debug("Sent PONG response")
			} else {
				serverLogger.Debug("Received unknown message: %q", msgStr)
			}
		}
	})

	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	serverAddr := server.Addr().String()
	log.Printf("Server listening on %s", serverAddr)

	// Небольшая задержка для запуска сервера
	time.Sleep(100 * time.Millisecond)

	// Создание и подключение клиента
	client := NewClient(serverAddr, clientLogger)

	// Параметры соединения
	params := &cotp.IsoConnectionParameters{
		RemoteTSelector: cotp.TSelector{Value: []byte{0, 1}},
		LocalTSelector:  cotp.TSelector{Value: []byte{0, 1}},
	}

	// Подключение
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientLogger.Debug("Connecting to server at %s...", serverAddr)
	if err := client.Connect(ctx, params); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	clientLogger.Debug("Connected successfully")

	// Отправка ping сообщений раз в секунду
	startTime := time.Now()
	pingCount := 0

	for time.Since(startTime) < duration {
		pingCount++

		// Отправка ping
		pingData := []byte("ping")
		clientLogger.Debug("Sending PING message #%d", pingCount)
		if err := client.SendData(pingData); err != nil {
			log.Printf("Failed to send ping: %v", err)
			break
		}

		// Получение pong
		pongData, err := client.ReceiveData(2 * time.Second)
		if err != nil {
			log.Printf("Failed to receive pong: %v", err)
			break
		}

		// Проверка ответа
		pongStr := string(pongData)
		if pongStr == "pong" {
			clientLogger.Debug("Received PONG response #%d", pingCount)
		} else {
			clientLogger.Debug("Received unexpected response: %q", pongStr)
		}

		// Ожидание до следующей секунды
		elapsed := time.Since(startTime)
		nextPingTime := time.Duration(pingCount) * time.Second
		if nextPingTime > elapsed {
			sleepTime := nextPingTime - elapsed
			time.Sleep(sleepTime)
		}
	}

	clientLogger.Debug("Finished ping-pong exchange (%d messages)", pingCount)
	log.Printf("Demo completed. Sent %d ping messages", pingCount)

	// Небольшая задержка перед закрытием
	time.Sleep(200 * time.Millisecond)
	log.Println("Shutting down...")
}
