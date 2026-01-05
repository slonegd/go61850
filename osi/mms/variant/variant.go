package variant

import (
	"strconv"
	"strings"
	"time"
)

// Type представляет тип значения в MMS Data
type Type int

const (
	// Float32 - IEEE 754 single precision floating-point (32-bit)
	Float32 Type = iota
	// Int32 - 32-bit signed integer
	Int32
	// UTCTime - UTC time согласно ISO/IEC 9506-2 (8 байт: 4 байта секунды + 3 байта доля секунды + 1 байт качество)
	UTCTime
	// BitString - bit string согласно ISO/IEC 9506-2
	BitString
	// Bool - boolean (будет добавлено позже)
	// String - visible string (будет добавлено позже)
)

// String возвращает строковое представление Type
func (t Type) String() string {
	switch t {
	case Float32:
		return "float32"
	case Int32:
		return "int32"
	case UTCTime:
		return "utc-time"
	case BitString:
		return "bit-string"
	default:
		// Используем strings.Builder вместо fmt.Sprintf для лучшей производительности
		var b strings.Builder
		b.WriteString("unknown(")
		b.WriteString(strconv.Itoa(int(t)))
		b.WriteByte(')')
		return b.String()
	}
}

// Variant представляет типизированное значение MMS Data
// Согласно ISO/IEC 9506-2, Data может быть разных типов:
// - floating-point (IEEE 754 single precision)
// - integer (32-bit signed)
// - utc-time (UTC time, 8 байт)
// - bit-string (BIT STRING)
// - bool (boolean)
// - visible-string
// и т.д.
type Variant struct {
	typ   Type
	value interface{}
}

// Type возвращает тип значения Variant
func (v *Variant) Type() Type {
	return v.typ
}

// Float32 возвращает значение как float32
// Если тип не совпадает, пытается преобразовать значение к float32
// Возвращает 0.0 если преобразование невозможно
func (v *Variant) Float32() float32 {
	if v == nil {
		return 0.0
	}

	switch val := v.value.(type) {
	case float32:
		return val
	case int32:
		return float32(val)
	default:
		return 0.0
	}
}

// Int32 возвращает значение как int32
// Если тип не совпадает, пытается преобразовать значение к int32
// Возвращает 0 если преобразование невозможно
func (v *Variant) Int32() int32 {
	if v == nil {
		return 0
	}

	switch val := v.value.(type) {
	case int32:
		return val
	case float32:
		return int32(val)
	default:
		return 0
	}
}

// NewFloat32Variant создаёт новый Variant с float32 значением
func NewFloat32Variant(value float32) *Variant {
	return &Variant{
		typ:   Float32,
		value: value,
	}
}

// NewInt32Variant создаёт новый Variant с int32 значением
func NewInt32Variant(value int32) *Variant {
	return &Variant{
		typ:   Int32,
		value: value,
	}
}

// Time возвращает значение как time.Time
// Если тип не совпадает, возвращает нулевое время
func (v *Variant) Time() time.Time {
	if v == nil {
		return time.Time{}
	}

	switch val := v.value.(type) {
	case time.Time:
		return val
	default:
		return time.Time{}
	}
}

// NewUTCTimeVariant создаёт новый Variant с time.Time значением
func NewUTCTimeVariant(value time.Time) *Variant {
	return &Variant{
		typ:   UTCTime,
		value: value,
	}
}

// BitStringValue представляет значение bit-string
// Содержит данные и количество бит (размер может быть не кратен 8)
type BitStringValue struct {
	// Data содержит байты bit-string
	Data []byte
	// BitSize количество значащих бит (может быть меньше len(Data)*8)
	BitSize int
}

// NewBitStringVariant создаёт новый Variant с BitStringValue значением
func NewBitStringVariant(data []byte, bitSize int) *Variant {
	return &Variant{
		typ: BitString,
		value: BitStringValue{
			Data:    data,
			BitSize: bitSize,
		},
	}
}

// BitString возвращает значение как BitStringValue
// Если тип не совпадает, возвращает пустое значение
func (v *Variant) BitString() BitStringValue {
	if v == nil {
		return BitStringValue{}
	}

	switch val := v.value.(type) {
	case BitStringValue:
		return val
	default:
		return BitStringValue{}
	}
}

// String возвращает строковое представление Variant в формате "тип(значение)"
// Например: "float32(4.2)"
// Использует strings.Builder вместо fmt.Sprintf для лучшей производительности GC
func (v *Variant) String() string {
	if v == nil {
		return "<nil>"
	}

	var b strings.Builder
	b.WriteString(v.typ.String())
	b.WriteByte('(')

	switch v.typ {
	case Float32:
		val := v.Float32()
		// Используем strconv.FormatFloat для форматирования без fmt.Sprintf
		b.WriteString(strconv.FormatFloat(float64(val), 'g', -1, 32))
	case Int32:
		val := v.Int32()
		// Используем strconv.FormatInt для форматирования без fmt.Sprintf
		b.WriteString(strconv.FormatInt(int64(val), 10))
	case UTCTime:
		val := v.Time()
		// Форматируем время в RFC3339 с наносекундами
		b.WriteString(val.Format(time.RFC3339Nano))
	case BitString:
		val := v.BitString()
		// Форматируем bit-string в бинарном формате с подчеркиваниями для читаемости
		// Группируем биты справа налево (младшие разряды): первая группа 1-4 бита, остальные по 4
		// Например: 0b0_0000_0000_0000 для 13 бит
		b.WriteString("0b")
		if val.BitSize == 0 {
			b.WriteString("0")
		} else {
			// Собираем все биты в массив (слева направо, старшие биты первыми)
			allBits := make([]byte, val.BitSize)
			bitIdx := 0
			for i := 0; i < len(val.Data) && bitIdx < val.BitSize; i++ {
				byteVal := val.Data[i]
				for j := 7; j >= 0 && bitIdx < val.BitSize; j-- {
					if (byteVal & (1 << j)) != 0 {
						allBits[bitIdx] = '1'
					} else {
						allBits[bitIdx] = '0'
					}
					bitIdx++
				}
			}
			// Форматируем справа налево (младшие разряды первыми)
			// Первая группа: остаток от деления на 4 (1-4 бита)
			// Остальные группы: по 4 бита
			firstGroupSize := val.BitSize % 4
			if firstGroupSize == 0 {
				firstGroupSize = 4
			}
			// Выводим первую группу (младшие биты, справа налево)
			// allBits содержит биты слева направо (старший бит первым)
			// Нужно вывести младшие биты первыми, то есть с конца массива
			for i := val.BitSize - 1; i >= val.BitSize-firstGroupSize; i-- {
				b.WriteByte(allBits[i])
			}
			// Выводим остальные группы по 4 бита (справа налево)
			for remaining := val.BitSize - firstGroupSize; remaining > 0; remaining -= 4 {
				b.WriteByte('_')
				groupEnd := remaining
				groupStart := remaining - 4
				if groupStart < 0 {
					groupStart = 0
				}
				// Выводим биты группы справа налево (младшие первыми)
				for i := groupEnd - 1; i >= groupStart; i-- {
					b.WriteByte(allBits[i])
				}
			}
		}
	default:
		b.WriteString("<unknown>")
	}

	b.WriteByte(')')
	return b.String()
}
