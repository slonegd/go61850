package ber

// TagClass represents the class of a BER tag
// The two high-order bits of the identifier octets are used to encode the class.
type TagClass byte

// Tag classes as defined in X.690
const (
	ClassUniversal       TagClass = 0x00 // 0b00000000 - Universal class (ASN.1 built-in types)
	ClassApplication     TagClass = 0x40 // 0b01000000 - Application class (defined by the application)
	ClassContextSpecific TagClass = 0x80 // 0b10000000 - Context-specific class
	ClassPrivate         TagClass = 0xC0 // 0b11000000 - Private class (defined in private specifications)
)

// TagForm represents the form of a BER tag
// The next bit (bit 5) indicates if the type is primitive or constructed.
type TagForm byte

// Tag forms as defined in X.690
const (
	FormPrimitive   TagForm = 0x00 // 0b00000000 - Primitive encoding
	FormConstructed TagForm = 0x20 // 0b00100000 - Constructed encoding (contains other types)
)

// Tag represents a BER tag value
type Tag byte

// Universal tags as defined in X.690
const (
	Boolean          Tag = 0x01 // BOOLEAN
	Integer          Tag = 0x02 // INTEGER
	BitString        Tag = 0x03 // BIT STRING
	OctetString      Tag = 0x04 // OCTET STRING
	Null             Tag = 0x05 // NULL
	ObjectIdentifier Tag = 0x06 // OBJECT IDENTIFIER
	ObjectDescriptor Tag = 0x07 // ObjectDescriptor
	External         Tag = 0x08 // EXTERNAL
	Real             Tag = 0x09 // REAL
	Enumerated       Tag = 0x0A // ENUMERATED
	EmbeddedPDV      Tag = 0x0B // EMBEDDED PDV
	UTF8String       Tag = 0x0C // UTF8String
	RelativeOID      Tag = 0x0D // RELATIVE-OID
	// 0x0E-0x0F are reserved for future use
	Sequence        Tag = 0x10 // SEQUENCE, SEQUENCE OF
	Set             Tag = 0x11 // SET, SET OF
	NumericString   Tag = 0x12 // NumericString
	PrintableString Tag = 0x13 // PrintableString
	T61String       Tag = 0x14 // T61String (TeletexString)
	VideotexString  Tag = 0x15 // VideotexString
	IA5String       Tag = 0x16 // IA5String
	UTCTime         Tag = 0x17 // UTCTime
	GeneralizedTime Tag = 0x18 // GeneralizedTime
	GraphicString   Tag = 0x19 // GraphicString
	VisibleString   Tag = 0x1A // VisibleString (ISO646String)
	GeneralString   Tag = 0x1B // GeneralString
	UniversalString Tag = 0x1C // UniversalString
	CharacterString Tag = 0x1D // CHARACTER STRING
	BMPString       Tag = 0x1E // BMPString
	// 0x1F is reserved
)

// Frequently used constructed universal tags
const (
	SequenceConstructed Tag = Sequence | Tag(FormConstructed) // 0x30
	SetConstructed      Tag = Set | Tag(FormConstructed)      // 0x31
	ExternalConstructed Tag = External | Tag(FormConstructed) // 0x28
)

// MakeTag creates a BER tag from class, form, and tag number
func MakeTag(class TagClass, form TagForm, tagNumber Tag) Tag {
	// For tag numbers less than 31 (0x1F), we can use a single byte
	if tagNumber < 0x1F {
		return Tag(byte(class) | byte(form) | byte(tagNumber))
	}
	// For tag numbers >= 31, we'd need to use multiple bytes (not implemented here)
	return Tag(byte(class) | byte(form) | 0x1F) // 0x1F indicates more bytes follow (not fully implemented)
}

// MakeApplicationTag creates an application-specific tag
func MakeApplicationTag(tagNumber byte, constructed bool) Tag {
	form := FormPrimitive
	if constructed {
		form = FormConstructed
	}
	return MakeTag(ClassApplication, form, Tag(tagNumber))
}

// MakeContextSpecificTag creates a context-specific tag
func MakeContextSpecificTag(tagNumber byte, constructed bool) Tag {
	form := FormPrimitive
	if constructed {
		form = FormConstructed
	}
	return MakeTag(ClassContextSpecific, form, Tag(tagNumber))
}

// MakeUniversalTag creates a universal tag
func MakeUniversalTag(tagNumber Tag, constructed bool) Tag {
	form := FormPrimitive
	if constructed {
		form = FormConstructed
	}
	return MakeTag(ClassUniversal, form, tagNumber)
}

// Common BER tags used in the project
const (
	// Application class, constructed
	Application0Constructed Tag = 0x60 // Application 0, Constructed
	Application1Constructed Tag = 0x61 // Application 1, Constructed

	// Context-specific, constructed
	ContextSpecific0Constructed  Tag = 0xA0
	ContextSpecific1Constructed  Tag = 0xA1
	ContextSpecific2Constructed  Tag = 0xA2
	ContextSpecific3Constructed  Tag = 0xA3
	ContextSpecific4Constructed  Tag = 0xA4
	ContextSpecific6Constructed  Tag = 0xA6
	ContextSpecific7Constructed  Tag = 0xA7
	ContextSpecific12Constructed Tag = 0xAC
	ContextSpecific30Constructed Tag = 0xBE
)

// Common context-specific primitive tags
const (
	ContextSpecific0Primitive  Tag = 0x80
	ContextSpecific1Primitive  Tag = 0x81
	ContextSpecific2Primitive  Tag = 0x82
	ContextSpecific10Primitive Tag = 0x8A
	ContextSpecific11Primitive Tag = 0x8B
)

// Common BER length values
const (
	Length1 = 1
	Length2 = 2
	Length3 = 3
	Length4 = 4
)
