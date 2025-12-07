package logger

import "log"

// Logger интерфейс для логирования пакетов всех уровней OSI
type Logger interface {
	Debug(format string, v ...any)
}

// stdLogger реализует Logger через стандартный пакет log
type stdLogger struct {
	category string
}

// NewLogger создает новый логгер с указанной категорией
func NewLogger(category string) Logger {
	return &stdLogger{category: category}
}

func (l *stdLogger) Debug(format string, v ...any) {
	if l.category == "" {
		log.Printf(format, v...)
	} else {
		log.Printf("["+l.category+"] "+format, v...)
	}
}

