package mms

import (
	"github.com/slonegd/go61850/ber"
)

// GetVariableAccessAttributesRequest представляет MMS GetVariableAccessAttributes Request PDU
// Структура согласно ISO/IEC 9506-2:
//
//	confirmed-RequestPDU ::= SEQUENCE {
//	  invokeID            [0] IMPLICIT Unsigned32,
//	  confirmedServiceRequest [1] CHOICE {
//	    getVariableAccessAttributes [6] GetVariableAccessAttributes-Request
//	  }
//	}
//
//	GetVariableAccessAttributes-Request ::= CHOICE {
//	  name [0] ObjectName
//	}
//
//	ObjectName ::= CHOICE {
//	  domain-specific [1] SEQUENCE {
//	    domainId [0] IMPLICIT VisibleString,
//	    itemId   [1] IMPLICIT VisibleString
//	  }
//	}
type GetVariableAccessAttributesRequest struct {
	// InvokeID - идентификатор вызова (обычно 2 для второго запроса)
	InvokeID uint32
	// DomainID - имя домена (например, "simpleIOGenericIO")
	DomainID string
	// ItemID - имя элемента (например, "GGIO1$MX")
	ItemID string
}

// Bytes кодирует GetVariableAccessAttributesRequest в BER-кодированный пакет MMS confirmed-RequestPDU
// Структура пакета (из wireshark):
// a0 26 - confirmed-RequestPDU (Context-specific 0, Constructed, длина 38 байт)
//
//	02 01 02 - invokeID (INTEGER, длина 1, значение 2)
//	a6 21 - confirmedServiceRequest: getVariableAccessAttributes (Context-specific 6, Constructed, длина 33 байт)
//	   a0 1f - getVariableAccessAttributes: name (Context-specific 0, Constructed, длина 31 байт)
//	      a1 1d - name: domain-specific (Context-specific 1, Constructed, длина 29 байт)
//	         1a 11 - domainId (VisibleString, длина 17 байт): "simpleIOGenericIO"
//	         1a 08 - itemId (VisibleString, длина 8 байт): "GGIO1$MX"
func (r *GetVariableAccessAttributesRequest) Bytes() []byte {
	buffer := make([]byte, 512)
	bufPos := 0

	// Сначала строим внутреннее содержимое, чтобы знать его размер
	innerContent := r.buildRequestContent()

	// Кодируем confirmed-RequestPDU (Context-specific 0, Constructed)
	// 0xa0 = Context-specific 0, Constructed
	bufPos = ber.EncodeTL(ber.ContextSpecific0Constructed, uint32(len(innerContent)), buffer, bufPos)
	copy(buffer[bufPos:], innerContent)
	bufPos += len(innerContent)

	return buffer[:bufPos]
}

// buildRequestContent собирает содержимое confirmed-RequestPDU
func (r *GetVariableAccessAttributesRequest) buildRequestContent() []byte {
	buffer := make([]byte, 512)
	bufPos := 0

	// invokeID (INTEGER)
	// В MMS invokeID кодируется как INTEGER
	// Используем обычный INTEGER (0x02), как в wireshark
	tempBuf := make([]byte, 256)
	tempPos := ber.EncodeUInt32(r.InvokeID, tempBuf, 0)
	intValue := tempBuf[0:tempPos]
	bufPos = ber.EncodeTL(ber.Integer, uint32(len(intValue)), buffer, bufPos)
	copy(buffer[bufPos:], intValue)
	bufPos += len(intValue)

	// confirmedServiceRequest: getVariableAccessAttributes (Context-specific 6, Constructed)
	// 0xa6 = Context-specific 6, Constructed
	getVarAccessAttrContent := r.buildGetVariableAccessAttributesRequest()
	bufPos = ber.EncodeTL(ber.ContextSpecific6Constructed, uint32(len(getVarAccessAttrContent)), buffer, bufPos)
	copy(buffer[bufPos:], getVarAccessAttrContent)
	bufPos += len(getVarAccessAttrContent)

	return buffer[:bufPos]
}

// buildGetVariableAccessAttributesRequest собирает содержимое getVariableAccessAttributes request
func (r *GetVariableAccessAttributesRequest) buildGetVariableAccessAttributesRequest() []byte {
	buffer := make([]byte, 512)
	bufPos := 0

	// getVariableAccessAttributes: name (Context-specific 0, Constructed)
	// 0xa0 = Context-specific 0, Constructed
	nameContent := r.buildObjectName()
	bufPos = ber.EncodeTL(ber.ContextSpecific0Constructed, uint32(len(nameContent)), buffer, bufPos)
	copy(buffer[bufPos:], nameContent)
	bufPos += len(nameContent)

	return buffer[:bufPos]
}

// buildObjectName собирает ObjectName в формате domain-specific
func (r *GetVariableAccessAttributesRequest) buildObjectName() []byte {
	buffer := make([]byte, 512)
	bufPos := 0

	// name: domain-specific (Context-specific 1, Constructed)
	// 0xa1 = Context-specific 1, Constructed
	domainSpecificContent := r.buildDomainSpecificName()
	bufPos = ber.EncodeTL(ber.ContextSpecific1Constructed, uint32(len(domainSpecificContent)), buffer, bufPos)
	copy(buffer[bufPos:], domainSpecificContent)
	bufPos += len(domainSpecificContent)

	return buffer[:bufPos]
}

// buildDomainSpecificName собирает domain-specific имя
func (r *GetVariableAccessAttributesRequest) buildDomainSpecificName() []byte {
	buffer := make([]byte, 512)
	bufPos := 0

	// domainId (VisibleString, 0x1a)
	bufPos = ber.EncodeStringWithTag(ber.VisibleString, r.DomainID, buffer, bufPos)

	// itemId (VisibleString, 0x1a)
	bufPos = ber.EncodeStringWithTag(ber.VisibleString, r.ItemID, buffer, bufPos)

	return buffer[:bufPos]
}

// NewGetVariableAccessAttributesRequest создаёт MMS GetVariableAccessAttributesRequest из domainID и itemID.
// invokeID устанавливается в 2 (стандартное значение для второго запроса после Initiate).
func NewGetVariableAccessAttributesRequest(domainID, itemID string) *GetVariableAccessAttributesRequest {
	return &GetVariableAccessAttributesRequest{
		InvokeID: 2, // TODO разхардкодить. Должен проставлять клиент
		DomainID: domainID,
		ItemID:   itemID,
	}
}
