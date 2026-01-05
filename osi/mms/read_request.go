package mms

import (
	"strings"

	"github.com/slonegd/go61850/ber"
)

// ReadRequest представляет MMS Read Request PDU
// Структура согласно ISO/IEC 9506-2:
//
//	confirmed-RequestPDU ::= SEQUENCE {
//	  invokeID            [0] IMPLICIT Unsigned32,
//	  confirmedServiceRequest [1] CHOICE {
//	    read [4] Read-Request
//	  }
//	}
//
//	Read-Request ::= SEQUENCE {
//	  variableAccessSpecification [0] CHOICE {
//	    listOfVariable [0] SEQUENCE OF VariableAccessSpecification
//	  }
//	}
//
//	VariableAccessSpecification ::= CHOICE {
//	  name [0] ObjectName
//	}
type ReadRequest struct {
	// InvokeID - идентификатор вызова (обычно 1 для первого запроса)
	InvokeID uint32
	// DomainID - имя домена (например, "simpleIOGenericIO")
	DomainID string
	// ItemID - имя элемента (например, "GGIO1$MX$AnIn1$mag$f" или "GGIO1.AnIn1.mag.f")
	ItemID string
}

// Bytes кодирует ReadRequest в BER-кодированный пакет MMS confirmed-RequestPDU
// Структура пакета (из wireshark):
// a0 38 - confirmed-RequestPDU (Context-specific 0, Constructed, длина 56 байт)
//
//	02 01 01 - invokeID (INTEGER, длина 1, значение 1)
//	a4 33 - confirmedServiceRequest: read (Context-specific 4, Constructed, длина 51 байт)
//	   a4 31 - read (Context-specific 4, Constructed, длина 49 байт)
//	      a0 2f - variableAccessSpecification: listOfVariable (Context-specific 0, Constructed, длина 47 байт)
//	         30 2d - listOfVariable (SEQUENCE, длина 45 байт)
//	            a0 2b - variableSpecification: name (Context-specific 0, Constructed, длина 43 байта)
//	               a1 29 - name: domain-specific (Context-specific 1, Constructed, длина 41 байт)
//	                  1a 11 - domainId (VisibleString, длина 17 байт): "simpleIOGenericIO"
//	                  1a 14 - itemId (VisibleString, длина 20 байт): "GGIO1$MX$AnIn1$mag$f"
func (r *ReadRequest) Bytes() []byte {
	buffer := make([]byte, 512)
	bufPos := 0

	// Сначала строим внутреннее содержимое, чтобы знать его размер
	innerContent := r.buildReadRequestContent()

	// Кодируем confirmed-RequestPDU (Context-specific 0, Constructed)
	// 0xa0 = Context-specific 0, Constructed
	bufPos = ber.EncodeTL(ber.ContextSpecific0Constructed, uint32(len(innerContent)), buffer, bufPos)
	copy(buffer[bufPos:], innerContent)
	bufPos += len(innerContent)

	return buffer[:bufPos]
}

// buildReadRequestContent собирает содержимое confirmed-RequestPDU
func (r *ReadRequest) buildReadRequestContent() []byte {
	buffer := make([]byte, 512)
	bufPos := 0

	// invokeID (Context-specific 0, INTEGER)
	// В MMS invokeID кодируется как INTEGER с контекстно-зависимым тегом [0] IMPLICIT
	// В wireshark видно 02 01 01, что означает INTEGER (0x02) с длиной 1 и значением 1
	// Это означает, что используется обычный INTEGER, а не Context-specific 0
	// Возможно, это особенность кодирования IMPLICIT или отображения wireshark
	// Используем обычный INTEGER, как показано в wireshark
	tempBuf := make([]byte, 256)
	tempPos := ber.EncodeUInt32(r.InvokeID, tempBuf, 0)
	intValue := tempBuf[0:tempPos]
	// invokeID кодируется как обычный INTEGER (0x02), как в wireshark
	bufPos = ber.EncodeTL(ber.Integer, uint32(len(intValue)), buffer, bufPos)
	copy(buffer[bufPos:], intValue)
	bufPos += len(intValue)

	// confirmedServiceRequest: read (Context-specific 4, Constructed)
	// В wireshark видно a4, что означает Context-specific 4, Constructed
	// Это соответствует тегу [1] в структуре confirmed-RequestPDU
	// Но в wireshark показано a4 (Context-specific 4), используем его
	readRequestContent := r.buildReadServiceRequest()
	bufPos = ber.EncodeTL(ber.ContextSpecific4Constructed, uint32(len(readRequestContent)), buffer, bufPos)
	copy(buffer[bufPos:], readRequestContent)
	bufPos += len(readRequestContent)

	return buffer[:bufPos]
}

// buildReadServiceRequest собирает содержимое read service request
func (r *ReadRequest) buildReadServiceRequest() []byte {
	buffer := make([]byte, 512)
	bufPos := 0

	// read (Context-specific 1, Constructed)
	// В wireshark видно a1 31, что означает Context-specific 1, Constructed, длина 49
	// Это соответствует тегу [1] для read в структуре confirmedServiceRequest
	readContent := r.buildReadContent()
	bufPos = ber.EncodeTL(ber.ContextSpecific1Constructed, uint32(len(readContent)), buffer, bufPos)
	copy(buffer[bufPos:], readContent)
	bufPos += len(readContent)

	return buffer[:bufPos]
}

// buildReadContent собирает содержимое Read-Request
func (r *ReadRequest) buildReadContent() []byte {
	buffer := make([]byte, 512)
	bufPos := 0

	// variableAccessSpecification: listOfVariable (Context-specific 0, Constructed)
	listOfVariableContent := r.buildListOfVariable()
	bufPos = ber.EncodeTL(ber.ContextSpecific0Constructed, uint32(len(listOfVariableContent)), buffer, bufPos)
	copy(buffer[bufPos:], listOfVariableContent)
	bufPos += len(listOfVariableContent)

	return buffer[:bufPos]
}

// buildListOfVariable собирает SEQUENCE OF VariableAccessSpecification
func (r *ReadRequest) buildListOfVariable() []byte {
	buffer := make([]byte, 512)
	bufPos := 0

	// listOfVariable (SEQUENCE, Constructed)
	variableSpecContent := r.buildVariableSpecification()
	bufPos = ber.EncodeTL(ber.SequenceConstructed, uint32(len(variableSpecContent)), buffer, bufPos)
	copy(buffer[bufPos:], variableSpecContent)
	bufPos += len(variableSpecContent)

	return buffer[:bufPos]
}

// buildVariableSpecification собирает VariableAccessSpecification
func (r *ReadRequest) buildVariableSpecification() []byte {
	buffer := make([]byte, 512)
	bufPos := 0

	// variableSpecification: name (Context-specific 0, Constructed)
	nameContent := r.buildObjectName()
	bufPos = ber.EncodeTL(ber.ContextSpecific0Constructed, uint32(len(nameContent)), buffer, bufPos)
	copy(buffer[bufPos:], nameContent)
	bufPos += len(nameContent)

	return buffer[:bufPos]
}

// buildObjectName собирает ObjectName в формате domain-specific
func (r *ReadRequest) buildObjectName() []byte {
	buffer := make([]byte, 512)
	bufPos := 0

	// name: domain-specific (Context-specific 1, Constructed)
	domainSpecificContent := r.buildDomainSpecificName()
	bufPos = ber.EncodeTL(ber.ContextSpecific1Constructed, uint32(len(domainSpecificContent)), buffer, bufPos)
	copy(buffer[bufPos:], domainSpecificContent)
	bufPos += len(domainSpecificContent)

	return buffer[:bufPos]
}

// buildDomainSpecificName собирает domain-specific имя
func (r *ReadRequest) buildDomainSpecificName() []byte {
	buffer := make([]byte, 512)
	bufPos := 0

	// domainId (VisibleString, 0x1a)
	bufPos = ber.EncodeStringWithTag(ber.VisibleString, r.DomainID, buffer, bufPos)

	// itemId (VisibleString, 0x1a)
	bufPos = ber.EncodeStringWithTag(ber.VisibleString, r.ItemID, buffer, bufPos)

	return buffer[:bufPos]
}

// FunctionalConstraint представляет функциональное ограничение IEC 61850
type FunctionalConstraint string

const (
	FCNone FunctionalConstraint = ""   // Нет функционального ограничения
	FCMX   FunctionalConstraint = "MX" // Measurand (измеряемая величина)
	FCST   FunctionalConstraint = "ST" // Status (статус)
	FCSP   FunctionalConstraint = "SP" // SetPoint (уставка)
	FCSV   FunctionalConstraint = "SV" // Substitution Value (подстановочное значение)
	FCCF   FunctionalConstraint = "CF" // Configuration (конфигурация)
	FCDC   FunctionalConstraint = "DC" // Description (описание)
	FCSG   FunctionalConstraint = "SG" // Setting Group (группа уставок)
	FCSE   FunctionalConstraint = "SE" // Setting Group Editable (редактируемая группа уставок)
	FCSR   FunctionalConstraint = "SR" // Service Response (ответ сервиса)
	FCOR   FunctionalConstraint = "OR" // Operate (операция)
	FCBL   FunctionalConstraint = "BL" // Blocking (блокировка)
	FCEX   FunctionalConstraint = "EX" // Extended Definition (расширенное определение)
	FCCO   FunctionalConstraint = "CO" // Control (управление)
)

// NewReadRequestFromObjectName создаёт MMS ReadRequest из objectName и FunctionalConstraint.
// Разбирает objectName на domainID и itemID, преобразует itemID в формат MMS с учётом функционального ограничения.
//
// Формат objectName: "domain/item" или "item"
// Пример: "simpleIOGenericIO/GGIO1.AnIn1.mag.f" -> domainID="simpleIOGenericIO", itemID="GGIO1.AnIn1.mag.f"
// Или: "GGIO1.AnIn1.mag.f" -> domainID="simpleIOGenericIO" (дефолтный), itemID="GGIO1.AnIn1.mag.f"
//
// Преобразование itemID в формат MMS:
// - Если указан FunctionalConstraint (fc), первая точка заменяется на $FC$ (например, $MX$)
// - Остальные точки заменяются на $
// - Пример: "GGIO1.AnIn1.mag.f" с FC_MX -> "GGIO1$MX$AnIn1$mag$f"
// - Если FC не указан, все точки заменяются на $
//
// invokeID устанавливается в 1 (стандартное значение для первого запроса).
func NewReadRequest(objectName string, fc FunctionalConstraint) *ReadRequest {
	// Разбираем objectName на domainID и itemID
	// Формат: "domain/item" или просто "item"
	var domainID, itemID string
	if idx := strings.Index(objectName, "/"); idx >= 0 {
		domainID = objectName[:idx]
		itemID = objectName[idx+1:]
	} else {
		// Если разделителя нет, используем весь objectName как itemID
		// domainID будет пустым (или можно использовать дефолтный)
		itemID = objectName
		// Для примера из wireshark используем "simpleIOGenericIO" как дефолтный domain
		// В реальности это должно быть настроено или получено из конфигурации
		if domainID == "" {
			domainID = "simpleIOGenericIO"
		}
	}

	// Преобразуем точки в доллары для itemID с учетом функционального ограничения
	// Логика согласно MmsMapping_createMmsVariableNameFromObjectReference:
	// - Первая точка заменяется на $FC$ (например, $MX$)
	// - Остальные точки заменяются на $
	// Пример: "GGIO1.AnIn1.mag.f" с FC_MX -> "GGIO1$MX$AnIn1$mag$f"
	// Если FC не указан, все точки заменяются на $
	if !strings.Contains(itemID, "$") {
		if fc != FCNone && fc != "" {
			// Заменяем первую точку на $FC$
			if idx := strings.Index(itemID, "."); idx >= 0 {
				itemID = itemID[:idx] + "$" + string(fc) + "$" + itemID[idx+1:]
				// Заменяем остальные точки на $
				itemID = strings.ReplaceAll(itemID, ".", "$")
			} else {
				// Если точек нет, добавляем $FC$ в конец
				itemID = itemID + "$" + string(fc)
			}
		} else {
			// Если FC не указан, просто заменяем все точки на $
			itemID = strings.ReplaceAll(itemID, ".", "$")
		}
	}

	// invokeID = 1 для первого запроса
	return &ReadRequest{1, domainID, itemID}
}
