package mms

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/slonegd/go61850/osi/mms/variant"
	"github.com/stretchr/testify/assert"
)

// parseHexString парсит hex строку в байты
// Удаляет пробелы, переносы строк и табы, затем парсит пары hex символов
func parseHexString(hexStr string) []byte {
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, "\n", "")
	hexStr = strings.ReplaceAll(hexStr, "\t", "")
	data := make([]byte, 0, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		if i+1 >= len(hexStr) {
			break
		}
		var b byte
		if _, err := fmt.Sscanf(hexStr[i:i+2], "%02x", &b); err != nil {
			continue
		}
		data = append(data, b)
	}
	return data
}

func TestParseReadResponse(t *testing.T) {
	tests := []struct {
		name      string
		buffer    string // hex строка без пробелов
		want      ReadResponse
		wantError string
	}{
		{
			// Пример из комментария в read_response.go:
			// a0 0e - confirmed-ResponsePDU (длина содержимого 14 байт)
			//   02 01 01 - invokeID = 1 (3 байта)
			//   a4 09 - confirmedServiceResponse: read (длина 9 байт содержимого, 11 байт всего)
			//      a1 07 - read (длина 7 байт содержимого, 9 байт всего)
			//         87 05 - success floating-point (длина 5 байт содержимого, 7 байт всего)
			//            08 3d a8 83 7c - формат + значение (5 байт)
			// Итого содержимого: 3 + 11 = 14 байт
			name:   "стандартный формат с тегом 0xA0 - float32 успех",
			buffer: "a00e020101a409a1078705083da8837c",
			want: ReadResponse{
				InvokeID: 1,
				ListOfAccessResult: []AccessResult{{
					Success: true,
					Value:   variant.NewFloat32Variant(math.Float32frombits(0x3da8837c)),
				}},
			},
		},
		{
			// Пример из комментария в read_response.go:
			// a1 0e - read (длина 14 байт)
			//   02 01 01 - invokeID = 1
			//   a4 09 - confirmedServiceResponse: read (длина 9 байт)
			//      a1 07 - read (длина 7 байт)
			//         87 05 - success floating-point (длина 5 байт)
			//            08 3e df 52 cc - формат + значение
			name:   "формат с тегом 0xA1 - float32 успех",
			buffer: "a10e020101a409a1078705083edf52cc",
			want: ReadResponse{
				InvokeID: 1,
				ListOfAccessResult: []AccessResult{{
					Success: true,
					Value:   variant.NewFloat32Variant(math.Float32frombits(0x3edf52cc)),
				}},
			},
		},
		{
			// Формат без внешних тегов: invokeID + read response напрямую
			// 02 01 01 - invokeID = 1
			// a4 09 - confirmedServiceResponse: read (длина 9 байт)
			//    a1 07 - read (длина 7 байт)
			//       87 05 - success floating-point (длина 5 байт)
			//          08 3e df 52 cc - формат + значение
			name:   "формат без внешних тегов - float32 успех",
			buffer: "020101a409a1078705083edf52cc",
			want: ReadResponse{
				InvokeID: 1,
				ListOfAccessResult: []AccessResult{{
					Success: true,
					Value:   variant.NewFloat32Variant(math.Float32frombits(0x3edf52cc)),
				}},
			},
		},
		{
			// Формат с тегом 0xA1 и ошибкой доступа:
			// a1 0a - read (длина 10 байт содержимого)
			//   02 01 01 - invokeID = 1 (3 байта)
			//   a4 05 - confirmedServiceResponse: read (длина 5 байт содержимого)
			//      a1 03 - read (длина 3 байта содержимого)
			//         80 01 0a - failure (Context-specific 0), длина 1 байт, код ошибки 0x0a = 10
			// Код ошибки 10 = ObjectNonExistent
			name:   "формат с тегом 0xA1 - ошибка ObjectNonExistent",
			buffer: "a10a020101a405a10380010a",
			want: ReadResponse{
				InvokeID: 1,
				ListOfAccessResult: []AccessResult{{
					Success: false,
					Error:   &DataAccessError{ErrorCode: ObjectNonExistent},
				}},
			},
		},
		{
			name:      "пустой буфер",
			buffer:    "",
			wantError: "empty buffer",
		},
		{
			name:      "неверная длина - превышает размер буфера",
			buffer:    "a0ff020101",
			wantError: "failed to decode length: buffer overflow",
		},
		{
			// Пакет из wireshark:
			// a1 11 - read (Context-specific 1, Constructed, длина 17 байт)
			//   02 01 01 - invokeID = 1
			//   a4 0c - confirmedServiceResponse: read (Context-specific 4, Constructed, длина 12 байт)
			//      a1 0a - read (Context-specific 1, Constructed, длина 10 байт)
			//         91 08 - utc-time (Context-specific 17, Primitive, длина 8 байт)
			//            69 5b 76 07 - секунды (big-endian uint32) = 1767605767
			//            27 6c 8b - доля секунды = 2581643 единиц из 2^24
			//            80 - качество времени
			// Время: Jan 5, 2026 08:27:51.153999984 UTC
			name:   "UTC time успех",
			buffer: "a111020101a40ca10a9108695b7607276c8b80",
			want: ReadResponse{
				InvokeID: 1,
				ListOfAccessResult: []AccessResult{{
					Success: true,
					Value:   variant.NewUTCTimeVariant(time.Date(2026, 1, 5, 8, 27, 51, 153999984, time.UTC)),
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buffer := parseHexString(tt.buffer)
			got, err := ParseReadResponse(buffer)
			assert.Equal(t, tt.want, got, tt.name)
			assert.Equal(t, tt.wantError, func() string {
				if err == nil {
					return ""
				}
				return err.Error()
			}(), tt.name)
		})
	}
}
