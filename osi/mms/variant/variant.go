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
	default:
		b.WriteString("<unknown>")
	}

	b.WriteByte(')')
	return b.String()
}
