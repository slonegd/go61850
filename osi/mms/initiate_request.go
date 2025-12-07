package mms

import (
	"fmt"
	"strings"

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

// String возвращает строковое представление ServiceSupportedBit
func (b ServiceSupportedBit) String() string {
	switch b {
	case Status:
		return "Status"
	case GetNameList:
		return "GetNameList"
	case Identify:
		return "Identify"
	case Rename:
		return "Rename"
	case Read:
		return "Read"
	case Write:
		return "Write"
	case GetVariableAccessAttributes:
		return "GetVariableAccessAttributes"
	case DefineNamedVariable:
		return "DefineNamedVariable"
	case DefineScatteredAccess:
		return "DefineScatteredAccess"
	case GetScatteredAccessAttributes:
		return "GetScatteredAccessAttributes"
	case DeleteVariableAccess:
		return "DeleteVariableAccess"
	case DefineNamedVariableList:
		return "DefineNamedVariableList"
	case GetNamedVariableListAttributes:
		return "GetNamedVariableListAttributes"
	case DeleteNamedVariableList:
		return "DeleteNamedVariableList"
	case DefineNamedType:
		return "DefineNamedType"
	case GetNamedTypeAttributes:
		return "GetNamedTypeAttributes"
	case DeleteNamedType:
		return "DeleteNamedType"
	case Input:
		return "Input"
	case Output:
		return "Output"
	case TakeControl:
		return "TakeControl"
	case RelinquishControl:
		return "RelinquishControl"
	case DefineSemaphore:
		return "DefineSemaphore"
	case DeleteSemaphore:
		return "DeleteSemaphore"
	case ReportSemaphoreStatus:
		return "ReportSemaphoreStatus"
	case ReportPoolSemaphoreStatus:
		return "ReportPoolSemaphoreStatus"
	case ReportSemaphoreEntryStatus:
		return "ReportSemaphoreEntryStatus"
	case InitiateDownloadSequence:
		return "InitiateDownloadSequence"
	case DownloadSegment:
		return "DownloadSegment"
	case TerminateDownloadSequence:
		return "TerminateDownloadSequence"
	case InitiateUploadSequence:
		return "InitiateUploadSequence"
	case UploadSegment:
		return "UploadSegment"
	case TerminateUploadSequence:
		return "TerminateUploadSequence"
	case RequestDomainDownload:
		return "RequestDomainDownload"
	case RequestDomainUpload:
		return "RequestDomainUpload"
	case LoadDomainContent:
		return "LoadDomainContent"
	case StoreDomainContent:
		return "StoreDomainContent"
	case DeleteDomain:
		return "DeleteDomain"
	case GetDomainAttributes:
		return "GetDomainAttributes"
	case CreateProgramInvocation:
		return "CreateProgramInvocation"
	case DeleteProgramInvocation:
		return "DeleteProgramInvocation"
	case Start:
		return "Start"
	case Stop:
		return "Stop"
	case Resume:
		return "Resume"
	case Reset:
		return "Reset"
	case Kill:
		return "Kill"
	case GetProgramInvocationAttributes:
		return "GetProgramInvocationAttributes"
	case ObtainFile:
		return "ObtainFile"
	case DefineEventCondition:
		return "DefineEventCondition"
	case DeleteEventCondition:
		return "DeleteEventCondition"
	case GetEventConditionAttributes:
		return "GetEventConditionAttributes"
	case ReportEventConditionStatus:
		return "ReportEventConditionStatus"
	case AlterEventConditionMonitoring:
		return "AlterEventConditionMonitoring"
	case TriggerEvent:
		return "TriggerEvent"
	case DefineEventAction:
		return "DefineEventAction"
	case DeleteEventAction:
		return "DeleteEventAction"
	case GetEventActionAttributes:
		return "GetEventActionAttributes"
	case ReportActionStatus:
		return "ReportActionStatus"
	case DefineEventEnrollment:
		return "DefineEventEnrollment"
	case DeleteEventEnrollment:
		return "DeleteEventEnrollment"
	case AlterEventEnrollment:
		return "AlterEventEnrollment"
	case ReportEventEnrollmentStatus:
		return "ReportEventEnrollmentStatus"
	case GetEventEnrollmentAttributes:
		return "GetEventEnrollmentAttributes"
	case AcknowledgeEventNotification:
		return "AcknowledgeEventNotification"
	case GetAlarmSummary:
		return "GetAlarmSummary"
	case GetAlarmEnrollmentSummary:
		return "GetAlarmEnrollmentSummary"
	case ReadJournal:
		return "ReadJournal"
	case WriteJournal:
		return "WriteJournal"
	case InitializeJournal:
		return "InitializeJournal"
	case ReportJournalStatus:
		return "ReportJournalStatus"
	case CreateJournal:
		return "CreateJournal"
	case DeleteJournal:
		return "DeleteJournal"
	case GetCapabilityList:
		return "GetCapabilityList"
	case FileOpen:
		return "FileOpen"
	case FileRead:
		return "FileRead"
	case FileClose:
		return "FileClose"
	case FileRename:
		return "FileRename"
	case FileDelete:
		return "FileDelete"
	case FileDirectory:
		return "FileDirectory"
	case UnsolicitedStatus:
		return "UnsolicitedStatus"
	case InformationReport:
		return "InformationReport"
	case EventNotification:
		return "EventNotification"
	case AttachToEventCondition:
		return "AttachToEventCondition"
	case AttachToSemaphore:
		return "AttachToSemaphore"
	case Conclude:
		return "Conclude"
	case Cancel:
		return "Cancel"
	default:
		return fmt.Sprintf("ServiceSupportedBit(%d)", b)
	}
}

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

// String возвращает строковое представление ParameterCBBBit
func (b ParameterCBBBit) String() string {
	switch b {
	case Str1:
		return "Str1"
	case Str2:
		return "Str2"
	case Vnam:
		return "Vnam"
	case Valt:
		return "Valt"
	case Vadr:
		return "Vadr"
	case Vsca:
		return "Vsca"
	case Tpy:
		return "Tpy"
	case Vlis:
		return "Vlis"
	case Real:
		return "Real"
	case SpareBit9:
		return "SpareBit9"
	case Cei:
		return "Cei"
	default:
		return fmt.Sprintf("ParameterCBBBit(%d)", b)
	}
}

const (
	// ServicesSupportedCallingBitmaskSize - размер битовой маски ServicesSupportedCalling в байтах
	// В MMS используется фиксированный размер 11 байт (85 бит данных + 3 бита padding)
	ServicesSupportedCallingBitmaskSize = 11

	// ProposedParameterCBBBitmaskSize - размер битовой маски ProposedParameterCBB в байтах
	// В MMS используется фиксированный размер 2 байта (11 бит данных + 5 бит padding)
	ProposedParameterCBBBitmaskSize = 2
)

// InitiateRequest содержит параметры для создания MMS Initiate Request PDU
type InitiateRequest struct {
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
	// ProposedParameterCBB - поддерживаемые параметры (слайс битов)
	ProposedParameterCBB []ParameterCBBBit
	// ServicesSupportedCalling - поддерживаемые услуги (слайс битов)
	ServicesSupportedCalling []ServiceSupportedBit
}

// InitiateRequestOption представляет функцию для изменения параметров InitiateRequest
type InitiateRequestOption func(*InitiateRequest)

// DefaultInitiateRequestParams возвращает параметры по умолчанию
// соответствующие значениям из C реализации libIEC61850
func DefaultInitiateRequestParams() *InitiateRequest {
	return &InitiateRequest{
		LocalDetailCalling:                65000,
		ProposedMaxServOutstandingCalling: 5,
		ProposedMaxServOutstandingCalled:  5,
		ProposedDataStructureNestingLevel: 10,
		ProposedVersionNumber:             1,
		// ProposedParameterCBB: значения по умолчанию из libIEC61850
		// Соответствует битовой маске: f100 (str1, str2, vnam, valt, vlis)
		ProposedParameterCBB: []ParameterCBBBit{
			Str1,
			Str2,
			Vnam,
			Valt,
			Vlis,
		},
		// ServicesSupportedCalling: значения по умолчанию из libIEC61850
		// Соответствует битовой маске: ee1c00000408000079ef18
		ServicesSupportedCalling: []ServiceSupportedBit{
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
		},
	}
}

// WithLocalDetailCalling устанавливает максимальный размер PDU
func WithLocalDetailCalling(size uint32) InitiateRequestOption {
	return func(p *InitiateRequest) {
		p.LocalDetailCalling = size
	}
}

// WithProposedMaxServOutstandingCalling устанавливает макс. одновременные запросы от клиента
func WithProposedMaxServOutstandingCalling(count uint32) InitiateRequestOption {
	return func(p *InitiateRequest) {
		p.ProposedMaxServOutstandingCalling = count
	}
}

// WithProposedMaxServOutstandingCalled устанавливает макс. одновременные запросы к клиенту
func WithProposedMaxServOutstandingCalled(count uint32) InitiateRequestOption {
	return func(p *InitiateRequest) {
		p.ProposedMaxServOutstandingCalled = count
	}
}

// WithProposedDataStructureNestingLevel устанавливает макс. уровень вложенности структур
func WithProposedDataStructureNestingLevel(level uint32) InitiateRequestOption {
	return func(p *InitiateRequest) {
		p.ProposedDataStructureNestingLevel = level
	}
}

// WithProposedVersionNumber устанавливает версию протокола MMS
func WithProposedVersionNumber(version uint32) InitiateRequestOption {
	return func(p *InitiateRequest) {
		p.ProposedVersionNumber = version
	}
}

// WithProposedParameterCBB устанавливает поддерживаемые параметры
func WithProposedParameterCBB(parameters []ParameterCBBBit) InitiateRequestOption {
	return func(p *InitiateRequest) {
		p.ProposedParameterCBB = parameters
	}
}

// WithServicesSupportedCalling устанавливает поддерживаемые услуги
func WithServicesSupportedCalling(services []ServiceSupportedBit) InitiateRequestOption {
	return func(p *InitiateRequest) {
		p.ServicesSupportedCalling = services
	}
}

// String реализует интерфейс fmt.Stringer для InitiateRequest.
// Для ProposedParameterCBB и ServicesSupportedCalling выводит список установленных битов,
// остальные поля выводятся как при %+v.
func (r *InitiateRequest) String() string {
	var parts []string

	parts = append(parts, fmt.Sprintf("LocalDetailCalling:%d", r.LocalDetailCalling))
	parts = append(parts, fmt.Sprintf("ProposedMaxServOutstandingCalling:%d", r.ProposedMaxServOutstandingCalling))
	parts = append(parts, fmt.Sprintf("ProposedMaxServOutstandingCalled:%d", r.ProposedMaxServOutstandingCalled))
	parts = append(parts, fmt.Sprintf("ProposedDataStructureNestingLevel:%d", r.ProposedDataStructureNestingLevel))
	parts = append(parts, fmt.Sprintf("ProposedVersionNumber:%d", r.ProposedVersionNumber))

	// ProposedParameterCBB - список установленных битов
	if len(r.ProposedParameterCBB) > 0 {
		bitNames := make([]string, len(r.ProposedParameterCBB))
		for i, bit := range r.ProposedParameterCBB {
			bitNames[i] = bit.String()
		}
		parts = append(parts, fmt.Sprintf("ProposedParameterCBB:[%s]", strings.Join(bitNames, " ")))
	} else {
		parts = append(parts, "ProposedParameterCBB:[]")
	}

	// ServicesSupportedCalling - список установленных битов
	if len(r.ServicesSupportedCalling) > 0 {
		bitNames := make([]string, len(r.ServicesSupportedCalling))
		for i, bit := range r.ServicesSupportedCalling {
			bitNames[i] = bit.String()
		}
		parts = append(parts, fmt.Sprintf("ServicesSupportedCalling:[%s]", strings.Join(bitNames, " ")))
	} else {
		parts = append(parts, "ServicesSupportedCalling:[]")
	}

	return fmt.Sprintf("InitiateRequest{%s}", strings.Join(parts, " "))
}

// Bytes кодирует InitiateRequest в BER-кодированный пакет.
// Структура пакета (из libIEC61850):
//
//	A8 (tag) + length + content
//	где content содержит:
//	  - 80 (localDetailCalling) + length + value
//	  - 81 (proposedMaxServOutstandingCalling) + length + value
//	  - 82 (proposedMaxServOutstandingCalled) + length + value
//	  - 83 (proposedDataStructureNestingLevel) + length + value
//	  - A4 (mmsInitRequestDetail) + length + detail_content
func (r *InitiateRequest) Bytes() []byte {
	// Буфер для построения пакета (достаточно большой размер)
	buffer := make([]byte, 1024)
	bufPos := 0

	// Сначала построим внутреннее содержимое, чтобы знать его размер
	innerContent := r.buildInitiateRequestContent()

	// Теперь кодируем основной тег и длину
	// 0xA8 = Application 8, Constructed (InitiateRequestApdu)
	bufPos = ber.EncodeTL(0xA8, uint32(len(innerContent)), buffer, bufPos)
	copy(buffer[bufPos:], innerContent)
	bufPos += len(innerContent)

	return buffer[:bufPos]
}

// NewInitiateRequest создаёт MMS InitiateRequest с параметрами по умолчанию.
// Можно передать опции для переопределения отдельных параметров.
func NewInitiateRequest(opts ...InitiateRequestOption) *InitiateRequest {
	params := DefaultInitiateRequestParams()
	for _, opt := range opts {
		opt(params)
	}
	return params
}

// BuildInitiateRequestPDU создаёт MMS InitiateRequestPDU с параметрами по умолчанию.
// Можно передать опции для переопределения отдельных параметров.
// Возвращает BER-кодированный пакет.
// Deprecated: используйте NewInitiateRequest().Bytes() вместо этой функции.
func BuildInitiateRequestPDU(opts ...InitiateRequestOption) []byte {
	return NewInitiateRequest(opts...).Bytes()
}

// BuildInitiateRequestPDUWithParams создаёт MMS InitiateRequestPDU с заданными параметрами.
// Deprecated: используйте InitiateRequest.Bytes() вместо этой функции.
func BuildInitiateRequestPDUWithParams(params *InitiateRequest) []byte {
	return params.Bytes()
}

// buildInitiateRequestContent собирает содержимое InitiateRequestPDU.
// Содержит четыре INTEGER параметра и mmsInitRequestDetail.
// Кодирование: для каждого параметра используется контекстно-зависимый тег (0x80-0x83)
// с компактным кодированием INTEGER значения (без ведущих нулей).
func (r *InitiateRequest) buildInitiateRequestContent() []byte {
	buffer := make([]byte, 1024)
	bufPos := 0

	// localDetailCalling (Context-specific 0, INTEGER)
	// Максимальный размер PDU, который может принять клиент
	tempBuf := make([]byte, 256)
	tempPos := ber.EncodeUInt32(r.LocalDetailCalling, tempBuf, 0)
	intValue := tempBuf[0:tempPos]
	bufPos = ber.EncodeTL(0x80, uint32(len(intValue)), buffer, bufPos)
	copy(buffer[bufPos:], intValue)
	bufPos += len(intValue)

	// proposedMaxServOutstandingCalling (Context-specific 1, INTEGER)
	// Максимальное количество одновременных запросов от клиента к серверу
	tempPos = ber.EncodeUInt32(r.ProposedMaxServOutstandingCalling, tempBuf, 0)
	intValue = tempBuf[0:tempPos]
	bufPos = ber.EncodeTL(0x81, uint32(len(intValue)), buffer, bufPos)
	copy(buffer[bufPos:], intValue)
	bufPos += len(intValue)

	// proposedMaxServOutstandingCalled (Context-specific 2, INTEGER)
	// Максимальное количество одновременных запросов от сервера к клиенту
	tempPos = ber.EncodeUInt32(r.ProposedMaxServOutstandingCalled, tempBuf, 0)
	intValue = tempBuf[0:tempPos]
	bufPos = ber.EncodeTL(0x82, uint32(len(intValue)), buffer, bufPos)
	copy(buffer[bufPos:], intValue)
	bufPos += len(intValue)

	// proposedDataStructureNestingLevel (Context-specific 3, INTEGER)
	// Максимальный уровень вложенности структур данных
	tempPos = ber.EncodeUInt32(r.ProposedDataStructureNestingLevel, tempBuf, 0)
	intValue = tempBuf[0:tempPos]
	bufPos = ber.EncodeTL(0x83, uint32(len(intValue)), buffer, bufPos)
	copy(buffer[bufPos:], intValue)
	bufPos += len(intValue)

	// mmsInitRequestDetail (Application 4, Constructed)
	// Содержит версию протокола, поддерживаемые параметры и услуги
	mmsDetail := r.buildMMSInitRequestDetail()
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
func (r *InitiateRequest) buildMMSInitRequestDetail() []byte {
	buffer := make([]byte, 512)
	bufPos := 0

	// proposedVersionNumber (Context-specific 0, INTEGER)
	// Версия протокола MMS (обычно 1)
	tempBuf := make([]byte, 256)
	tempPos := ber.EncodeUInt32(r.ProposedVersionNumber, tempBuf, 0)
	intValue := tempBuf[0:tempPos]
	bufPos = ber.EncodeTL(0x80, uint32(len(intValue)), buffer, bufPos)
	copy(buffer[bufPos:], intValue)
	bufPos += len(intValue)

	// proposedParameterCBB (Context-specific 1, BIT STRING)
	// Поддерживаемые параметры (Parameter CBB - Capability Bit Box)
	// BIT STRING кодируется как: tag + length + unused_bits + data
	// Для параметров используется 5 бит padding (неиспользуемых бит в последнем байте)
	// Конвертируем слайс битов в битовую маску
	paramCBBBytes := ber.EncodeBitmaskFromOffsets(r.ProposedParameterCBB, ProposedParameterCBBBitmaskSize)
	bufPos = ber.EncodeTL(0x81, uint32(len(paramCBBBytes)+1), buffer, bufPos)
	buffer[bufPos] = 0x05 // 5 бит неиспользуемых в последнем байте
	bufPos++
	copy(buffer[bufPos:], paramCBBBytes)
	bufPos += len(paramCBBBytes)

	// servicesSupportedCalling (Context-specific 2, BIT STRING)
	// Поддерживаемые услуги (Services Supported)
	// Для услуг используется 3 бита padding
	// Конвертируем слайс битов в битовую маску
	servicesBytes := ber.EncodeBitmaskFromOffsets(r.ServicesSupportedCalling, ServicesSupportedCallingBitmaskSize)
	bufPos = ber.EncodeTL(0x82, uint32(len(servicesBytes)+1), buffer, bufPos)
	buffer[bufPos] = 0x03 // 3 бита неиспользуемых в последнем байте
	bufPos++
	copy(buffer[bufPos:], servicesBytes)
	bufPos += len(servicesBytes)

	// Обёртка в Application 4 (mmsInitRequestDetail)
	// 0xA4 = Application 4, Constructed
	detail := buffer[:bufPos]
	result := make([]byte, 512)
	resultPos := ber.EncodeTL(0xA4, uint32(len(detail)), result, 0)
	copy(result[resultPos:], detail)
	resultPos += len(detail)

	return result[:resultPos]
}
