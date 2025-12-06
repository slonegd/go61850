package mms

import (
	"github.com/slonegd/go61850/ber"
)

// ServiceSupportedBit представляет номер бита в битовой маске ServicesSupportedCalling
type ServiceSupportedBit uint

const (
	Status ServiceSupportedBit = iota
	GetNameList
	Identify
	Rename
	Read
	Write
	GetVariableAccessAttributes
	DefineNamedVariable
	DefineScatteredAccess
	GetScatteredAccessAttributes
	DeleteVariableAccess
	DefineNamedVariableList
	GetNamedVariableListAttributes
	DeleteNamedVariableList
	DefineNamedType
	GetNamedTypeAttributes
	DeleteNamedType
	Input
	Output
	TakeControl
	RelinquishControl
	DefineSemaphore
	DeleteSemaphore
	ReportSemaphoreStatus
	ReportPoolSemaphoreStatus
	ReportSemaphoreEntryStatus
	InitiateDownloadSequence
	DownloadSegment
	TerminateDownloadSequence
	InitiateUploadSequence
	UploadSegment
	TerminateUploadSequence
	RequestDomainDownload
	RequestDomainUpload
	LoadDomainContent
	StoreDomainContent
	DeleteDomain
	GetDomainAttributes
	CreateProgramInvocation
	DeleteProgramInvocation
	Start
	Stop
	Resume
	Reset
	Kill
	GetProgramInvocationAttributes
	ObtainFile
	DefineEventCondition
	DeleteEventCondition
	GetEventConditionAttributes
	ReportEventConditionStatus
	AlterEventConditionMonitoring
	TriggerEvent
	DefineEventAction
	DeleteEventAction
	GetEventActionAttributes
	ReportActionStatus
	DefineEventEnrollment
	DeleteEventEnrollment
	AlterEventEnrollment
	ReportEventEnrollmentStatus
	GetEventEnrollmentAttributes
	AcknowledgeEventNotification
	GetAlarmSummary
	GetAlarmEnrollmentSummary
	ReadJournal
	WriteJournal
	InitializeJournal
	ReportJournalStatus
	CreateJournal
	DeleteJournal
	GetCapabilityList
	FileOpen
	FileRead
	FileClose
	FileRename
	FileDelete
	FileDirectory
	UnsolicitedStatus
	InformationReport
	EventNotification
	AttachToEventCondition
	AttachToSemaphore
	Conclude
	Cancel
)

// ParameterCBBBit представляет номер бита в битовой маске ProposedParameterCBB
type ParameterCBBBit uint

const (
	Str1 ParameterCBBBit = iota
	Str2
	Vnam
	Valt
	Vadr
	Vsca
	Tpy
	Vlis
	Real
	SpareBit9
	Cei
)

const (
	// ServicesSupportedCallingBitmaskSize - размер битовой маски ServicesSupportedCalling в байтах
	// В MMS используется фиксированный размер 11 байт (85 бит данных + 3 бита padding)
	ServicesSupportedCallingBitmaskSize = 11

	// ProposedParameterCBBBitmaskSize - размер битовой маски ProposedParameterCBB в байтах
	// В MMS используется фиксированный размер 2 байта (11 бит данных + 5 бит padding)
	ProposedParameterCBBBitmaskSize = 2
)

// InitiateRequestParams содержит параметры для создания MMS Initiate Request PDU
type InitiateRequestParams struct {
	// LocalDetailCalling - максимальный размер PDU (в байтах)
	LocalDetailCalling uint32
	// ProposedMaxServOutstandingCalling - максимальное количество одновременных запросов от клиента
	ProposedMaxServOutstandingCalling uint32
	// ProposedMaxServOutstandingCalled - максимальное количество одновременных запросов к серверу
	ProposedMaxServOutstandingCalled uint32
	// ProposedDataStructureNestingLevel - максимальный уровень вложенности структур данных
	ProposedDataStructureNestingLevel uint32
	// ProposedVersionNumber - версия протокола MMS
	ProposedVersionNumber uint32
	// ProposedParameterCBB - поддерживаемые параметры (bit string)
	ProposedParameterCBB []byte
	// ServicesSupportedCalling - поддерживаемые услуги (bit string)
	// Внутренне хранится как []byte для BER-кодирования
	ServicesSupportedCalling []byte
}

// InitiateRequestOption представляет функцию для изменения параметров InitiateRequest
type InitiateRequestOption func(*InitiateRequestParams)

// DefaultInitiateRequestParams возвращает параметры по умолчанию
// соответствующие значениям из C реализации libIEC61850
func DefaultInitiateRequestParams() *InitiateRequestParams {
	return &InitiateRequestParams{
		LocalDetailCalling:                65000,
		ProposedMaxServOutstandingCalling: 5,
		ProposedMaxServOutstandingCalled:  5,
		ProposedDataStructureNestingLevel: 10,
		ProposedVersionNumber:             1,
		// ProposedParameterCBB: значения по умолчанию из libIEC61850
		// Соответствует битовой маске: f100 (str1, str2, vnam, valt, vlis)
		ProposedParameterCBB: ber.EncodeBitmaskFromOffsets([]ParameterCBBBit{
			Str1,
			Str2,
			Vnam,
			Valt,
			Vlis,
		}, ProposedParameterCBBBitmaskSize),
		// ServicesSupportedCalling: значения по умолчанию из libIEC61850
		// Соответствует битовой маске: ee1c00000408000079ef18
		ServicesSupportedCalling: ber.EncodeBitmaskFromOffsets([]ServiceSupportedBit{
			Status,
			GetNameList,
			Identify,
			Read,
			Write,
			GetVariableAccessAttributes,
			DefineNamedVariableList,
			GetNamedVariableListAttributes,
			DeleteNamedVariableList,
			GetDomainAttributes,
			Kill,
			ReadJournal,
			WriteJournal,
			InitializeJournal,
			ReportJournalStatus,
			GetCapabilityList,
			FileOpen,
			FileRead,
			FileClose,
			FileDelete,
			FileDirectory,
			UnsolicitedStatus,
			InformationReport,
			Conclude,
			Cancel,
		}, ServicesSupportedCallingBitmaskSize),
	}
}

// WithLocalDetailCalling устанавливает максимальный размер PDU
func WithLocalDetailCalling(size uint32) InitiateRequestOption {
	return func(p *InitiateRequestParams) {
		p.LocalDetailCalling = size
	}
}

// WithProposedMaxServOutstandingCalling устанавливает макс. одновременные запросы от клиента
func WithProposedMaxServOutstandingCalling(count uint32) InitiateRequestOption {
	return func(p *InitiateRequestParams) {
		p.ProposedMaxServOutstandingCalling = count
	}
}

// WithProposedMaxServOutstandingCalled устанавливает макс. одновременные запросы к клиенту
func WithProposedMaxServOutstandingCalled(count uint32) InitiateRequestOption {
	return func(p *InitiateRequestParams) {
		p.ProposedMaxServOutstandingCalled = count
	}
}

// WithProposedDataStructureNestingLevel устанавливает макс. уровень вложенности структур
func WithProposedDataStructureNestingLevel(level uint32) InitiateRequestOption {
	return func(p *InitiateRequestParams) {
		p.ProposedDataStructureNestingLevel = level
	}
}

// WithProposedVersionNumber устанавливает версию протокола MMS
func WithProposedVersionNumber(version uint32) InitiateRequestOption {
	return func(p *InitiateRequestParams) {
		p.ProposedVersionNumber = version
	}
}

// WithProposedParameterCBB устанавливает поддерживаемые параметры
func WithProposedParameterCBB(parameters []ParameterCBBBit) InitiateRequestOption {
	return func(p *InitiateRequestParams) {
		p.ProposedParameterCBB = ber.EncodeBitmaskFromOffsets(parameters, ProposedParameterCBBBitmaskSize)
	}
}

// WithServicesSupportedCalling устанавливает поддерживаемые услуги
func WithServicesSupportedCalling(services []ServiceSupportedBit) InitiateRequestOption {
	return func(p *InitiateRequestParams) {
		p.ServicesSupportedCalling = ber.EncodeBitmaskFromOffsets(services, ServicesSupportedCallingBitmaskSize)
	}
}

// BuildInitiateRequestPDU создаёт MMS InitiateRequestPDU с параметрами по умолчанию.
// Можно передать опции для переопределения отдельных параметров.
// Возвращает BER-кодированный пакет.
func BuildInitiateRequestPDU(opts ...InitiateRequestOption) []byte {
	params := DefaultInitiateRequestParams()
	for _, opt := range opts {
		opt(params)
	}
	return BuildInitiateRequestPDUWithParams(params)
}

// BuildInitiateRequestPDUWithParams создаёт MMS InitiateRequestPDU с заданными параметрами.
// Структура пакета (из libIEC61850):
//
//	A8 (tag) + length + content
//	где content содержит:
//	  - 80 (localDetailCalling) + length + value
//	  - 81 (proposedMaxServOutstandingCalling) + length + value
//	  - 82 (proposedMaxServOutstandingCalled) + length + value
//	  - 83 (proposedDataStructureNestingLevel) + length + value
//	  - A4 (mmsInitRequestDetail) + length + detail_content
//
// Возвращает BER-кодированный пакет.
func BuildInitiateRequestPDUWithParams(params *InitiateRequestParams) []byte {
	// Буфер для построения пакета (достаточно большой размер)
	buffer := make([]byte, 1024)
	bufPos := 0

	// Сначала построим внутреннее содержимое, чтобы знать его размер
	innerContent := buildInitiateRequestContent(params)

	// Теперь кодируем основной тег и длину
	// 0xA8 = Application 8, Constructed (InitiateRequestApdu)
	bufPos = ber.EncodeTL(0xA8, uint32(len(innerContent)), buffer, bufPos)
	copy(buffer[bufPos:], innerContent)
	bufPos += len(innerContent)

	return buffer[:bufPos]
}

// buildInitiateRequestContent собирает содержимое InitiateRequestPDU.
// Содержит четыре INTEGER параметра и mmsInitRequestDetail.
// Кодирование: для каждого параметра используется контекстно-зависимый тег (0x80-0x83)
// с компактным кодированием INTEGER значения (без ведущих нулей).
func buildInitiateRequestContent(params *InitiateRequestParams) []byte {
	buffer := make([]byte, 1024)
	bufPos := 0

	// localDetailCalling (Context-specific 0, INTEGER)
	// Максимальный размер PDU, который может принять клиент
	tempBuf := make([]byte, 256)
	tempPos := ber.EncodeUInt32(params.LocalDetailCalling, tempBuf, 0)
	intValue := tempBuf[0:tempPos]
	bufPos = ber.EncodeTL(0x80, uint32(len(intValue)), buffer, bufPos)
	copy(buffer[bufPos:], intValue)
	bufPos += len(intValue)

	// proposedMaxServOutstandingCalling (Context-specific 1, INTEGER)
	// Максимальное количество одновременных запросов от клиента к серверу
	tempPos = ber.EncodeUInt32(params.ProposedMaxServOutstandingCalling, tempBuf, 0)
	intValue = tempBuf[0:tempPos]
	bufPos = ber.EncodeTL(0x81, uint32(len(intValue)), buffer, bufPos)
	copy(buffer[bufPos:], intValue)
	bufPos += len(intValue)

	// proposedMaxServOutstandingCalled (Context-specific 2, INTEGER)
	// Максимальное количество одновременных запросов от сервера к клиенту
	tempPos = ber.EncodeUInt32(params.ProposedMaxServOutstandingCalled, tempBuf, 0)
	intValue = tempBuf[0:tempPos]
	bufPos = ber.EncodeTL(0x82, uint32(len(intValue)), buffer, bufPos)
	copy(buffer[bufPos:], intValue)
	bufPos += len(intValue)

	// proposedDataStructureNestingLevel (Context-specific 3, INTEGER)
	// Максимальный уровень вложенности структур данных
	tempPos = ber.EncodeUInt32(params.ProposedDataStructureNestingLevel, tempBuf, 0)
	intValue = tempBuf[0:tempPos]
	bufPos = ber.EncodeTL(0x83, uint32(len(intValue)), buffer, bufPos)
	copy(buffer[bufPos:], intValue)
	bufPos += len(intValue)

	// mmsInitRequestDetail (Application 4, Constructed)
	// Содержит версию протокола, поддерживаемые параметры и услуги
	mmsDetail := buildMMSInitRequestDetail(params)
	copy(buffer[bufPos:], mmsDetail)
	bufPos += len(mmsDetail)

	return buffer[:bufPos]
}

// buildMMSInitRequestDetail собирает mmsInitRequestDetail (A4 - Application 4, Constructed).
// Содержит три элемента:
// - proposedVersionNumber (Context-specific 0, INTEGER) - версия протокола MMS
// - proposedParameterCBB (Context-specific 1, BIT STRING) - поддерживаемые параметры
// - servicesSupportedCalling (Context-specific 2, BIT STRING) - поддерживаемые услуги
// Значения берутся из параметров и кодируются в BER формате.
func buildMMSInitRequestDetail(params *InitiateRequestParams) []byte {
	buffer := make([]byte, 512)
	bufPos := 0

	// proposedVersionNumber (Context-specific 0, INTEGER)
	// Версия протокола MMS (обычно 1)
	tempBuf := make([]byte, 256)
	tempPos := ber.EncodeUInt32(params.ProposedVersionNumber, tempBuf, 0)
	intValue := tempBuf[0:tempPos]
	bufPos = ber.EncodeTL(0x80, uint32(len(intValue)), buffer, bufPos)
	copy(buffer[bufPos:], intValue)
	bufPos += len(intValue)

	// proposedParameterCBB (Context-specific 1, BIT STRING)
	// Поддерживаемые параметры (Parameter CBB - Capability Bit Box)
	// BIT STRING кодируется как: tag + length + unused_bits + data
	// Для параметров используется 5 бит padding (неиспользуемых бит в последнем байте)
	bufPos = ber.EncodeTL(0x81, uint32(len(params.ProposedParameterCBB)+1), buffer, bufPos)
	buffer[bufPos] = 0x05 // 5 бит неиспользуемых в последнем байте
	bufPos++
	copy(buffer[bufPos:], params.ProposedParameterCBB)
	bufPos += len(params.ProposedParameterCBB)

	// servicesSupportedCalling (Context-specific 2, BIT STRING)
	// Поддерживаемые услуги (Services Supported)
	// Для услуг используется 3 бита padding
	bufPos = ber.EncodeTL(0x82, uint32(len(params.ServicesSupportedCalling)+1), buffer, bufPos)
	buffer[bufPos] = 0x03 // 3 бита неиспользуемых в последнем байте
	bufPos++
	copy(buffer[bufPos:], params.ServicesSupportedCalling)
	bufPos += len(params.ServicesSupportedCalling)

	// Обёртка в Application 4 (mmsInitRequestDetail)
	// 0xA4 = Application 4, Constructed
	detail := buffer[:bufPos]
	result := make([]byte, 512)
	resultPos := ber.EncodeTL(0xA4, uint32(len(detail)), result, 0)
	copy(result[resultPos:], detail)
	resultPos += len(detail)

	return result[:resultPos]
}
