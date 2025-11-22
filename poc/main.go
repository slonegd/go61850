// Proof of Concept c MMS initiate-RequestPDU
// взял сишный клиент/сервер iec61850 и посмотрел вайршарком этот пакет
// в этом примере я создаю этот пакет на чистом го, получаю результат

// что получил из вайршарка с описанием значений байтов оттуда же:

// TPKT, Version: 3, Length: 187
// 03 00 00 bb

// ISO 8073/X.224 COTP Connection-Oriented Transport Protocol
// Length: 2
// PDU Type: DT Data (0x0f)
// .000 0000 = TPDU number: 0x00
// 1... .... = Last data unit: Yes
// 02 f0 80

// ISO 8327-1 OSI Session Protocol
// SPDU Type: CONNECT (CN) SPDU (13) | Length: 178
// 0d b2
// Connect Accept Item
// Parameter type: Connect Accept Item (5) | Parameter length: 6
// Protocol Options: Parameter type: Protocol Options (19) | Parameter length: 1 | Flags: 0x00
// Version Number: Parameter type: Version Number (22) | Parameter length: 1 | Flags: 0x02, Protocol Version 2
// 05 06 13 01 00 16 01 02
// Session Requirement
// Parameter type: Session Requirement (20)
// Parameter length: 2
// Flags: 0x0002, Duplex functional unit
// 14 02 00 02
// Calling Session Selector
// Parameter type: Calling Session Selector (51)
// Parameter length: 2
// Calling Session Selector: 0001
// 33 02 00 01
// Parameter type: Called Session Selector (51)
// Parameter length: 2
// Called Session Selector: 0001
// 34 02 00 01
// Session user data
// Parameter type: Session user data (193)
// Parameter length: 156
// c1 9c
// ПРИМЕЧАНИЕ: В дампе из Wireshark указано c1 9c (короткий формат, длина 156)
// Хотя 156 >= 128, но используется короткий формат согласно спецификации

// ISO 8823 OSI Presentation Protocol
// 31 81 99
// CP-type
// a0 03
// mode-selector: mode-value: normal-mode (1)
// 80 01 01
// normal-mode-parameters: до конца пакета
// a2 81 91
// calling-presentation-selector: 00000001
// 81 04 00 00 00 01
// called-presentation-selector: 00000001
// 82 04 00 00 00 01
// presentation-context-definition-list: 2 items
// a4 23
// Context-list item [0]
// 30 0f
// 02 01 01 - presentation-context-identifier: 1 (id-as-acse)
// 06 04 52 01 00 01 - abstract-syntax-name: 2.2.1.0.1 (id-as-acse)
// 30 04 06 02 51 01 - transfer-syntax-name-list: 1 item: Transfer-syntax-name: 2.1.1 (basic-encoding)
// Context-list item [1]
// 30 10
// 02 01 03 - presentation-context-identifier: 3 (mms-abstract-syntax-version1(1))
// 06 05 28 ca 22 02 01 - abstract-syntax-name: 1.0.9506.2.1 (mms-abstract-syntax-version1(1))
// 30 04 06 02 51 01 - Transfer-syntax-name: 2.1.1 (basic-encoding)
// user-data: fully-encoded-data (1)
// 61 5e
// fully-encoded-data: 1 item
// 30 5c
// PDV-list
// 02 01 01 - presentation-context-identifier: 1 (id-as-acse)
// a0 57 - presentation-data-values: single-ASN1-type (0)

// ISO 8650-1 OSI Association Control Service
// 60 55
// aarq
// a1 07 06 05 28 ca 22 02 03 - aSO-context-name: 1.0.9506.2.3 (MMS)
// a2 07 06 05 29 01 87 67 01 - called-AP-title: ap-title-form2: 1.1.1.999.1 (iso.1.1.999.1)
// a3 03 02 01 0c - called-AE-qualifier: aso-qualifier-form2: 12
// a6 06 06 04 29 01 87 67 - calling-AP-title: ap-title-form2: 1.1.1.999 (iso.1.1.999)
// a7 03 02 01 0c - calling-AE-qualifier: aso-qualifier-form2: 12
// be 2f 28 2d - user-information: 1 item: Association-data
// 02 01 03 - indirect-reference: 3
// a0 28 - encoding: single-ASN1-type (0)

// MMS
// a8 26 - initiate-RequestPDU
// 80 03 00 fd e8 - localDetailCalling: 65000
// 81 01 05 - proposedMaxServOutstandingCalling: 5
// 82 01 05 - proposedMaxServOutstandingCalled: 5
// 83 01 0a - proposedDataStructureNestingLevel: 10
// a4 16 - mmsInitRequestDetail
// 80 01 01 - proposedVersionNumber: 1
// 81 03 05 f1 00 - Padding: 5 | proposedParameterCBB: f100
// proposedParameterCBB: f100
// 1... .... = str1: True
// .1.. .... = str2: True
// ..1. .... = vnam: True
// ...1 .... = valt: True
// .... 0... = vadr: False
// .... .0.. = vsca: False
// .... ..0. = tpy: False
// .... ...1 = vlis: True
// 0... .... = real: False
// .0.. .... = spare_bit9: False
// ..0. .... = cei: False
// 82 0c 03 - Padding: 3
// ee 1c 00 00 04 08 00 00 79 ef 18
// servicesSupportedCalling: ee1c00000408000079ef18
// 1... .... = status: True
// .1.. .... = getNameList: True
// ..1. .... = identify: True
// ...0 .... = rename: False
// .... 1... = read: True
// .... .1.. = write: True
// .... ..1. = getVariableAccessAttributes: True
// .... ...0 = defineNamedVariable: False
// 0... .... = defineScatteredAccess: False
// .0.. .... = getScatteredAccessAttributes: False
// ..0. .... = deleteVariableAccess: False
// ...1 .... = defineNamedVariableList: True
// .... 1... = getNamedVariableListAttributes: True
// .... .1.. = deleteNamedVariableList: True
// .... ..0. = defineNamedType: False
// .... ...0 = getNamedTypeAttributes: False
// 0... .... = deleteNamedType: False
// .0.. .... = input: False
// ..0. .... = output: False
// ...0 .... = takeControl: False
// .... 0... = relinquishControl: False
// .... .0.. = defineSemaphore: False
// .... ..0. = deleteSemaphore: False
// .... ...0 = reportSemaphoreStatus: False
// 0... .... = reportPoolSemaphoreStatus: False
// .0.. .... = reportSemaphoreEntryStatus: False
// ..0. .... = initiateDownloadSequence: False
// ...0 .... = downloadSegment: False
// .... 0... = terminateDownloadSequence: False
// .... .0.. = initiateUploadSequence: False
// .... ..0. = uploadSegment: False
// .... ...0 = terminateUploadSequence: False
// 0... .... = requestDomainDownload: False
// .0.. .... = requestDomainUpload: False
// ..0. .... = loadDomainContent: False
// ...0 .... = storeDomainContent: False
// .... 0... = deleteDomain: False
// .... .1.. = getDomainAttributes: True
// .... ..0. = createProgramInvocation: False
// .... ...0 = deleteProgramInvocation: False
// 0... .... = start: False
// .0.. .... = stop: False
// ..0. .... = resume: False
// ...0 .... = reset: False
// .... 1... = kill: True
// .... .0.. = getProgramInvocationAttributes: False
// .... ..0. = obtainFile: False
// .... ...0 = defineEventCondition: False
// 0... .... = deleteEventCondition: False
// .0.. .... = getEventConditionAttributes: False
// ..0. .... = reportEventConditionStatus: False
// ...0 .... = alterEventConditionMonitoring: False
// .... 0... = triggerEvent: False
// .... .0.. = defineEventAction: False
// .... ..0. = deleteEventAction: False
// .... ...0 = getEventActionAttributes: False
// 0... .... = reportActionStatus: False
// .0.. .... = defineEventEnrollment: False
// ..0. .... = deleteEventEnrollment: False
// ...0 .... = alterEventEnrollment: False
// .... 0... = reportEventEnrollmentStatus: False
// .... .0.. = getEventEnrollmentAttributes: False
// .... ..0. = acknowledgeEventNotification: False
// .... ...0 = getAlarmSummary: False
// 0... .... = getAlarmEnrollmentSummary: False
// .1.. .... = readJournal: True
// ..1. .... = writeJournal: True
// ...1 .... = initializeJournal: True
// .... 1... = reportJournalStatus: True
// .... .0.. = createJournal: False
// .... ..0. = deleteJournal: False
// .... ...1 = getCapabilityList: True
// 1... .... = fileOpen: True
// .1.. .... = fileRead: True
// ..1. .... = fileClose: True
// ...0 .... = fileRename: False
// .... 1... = fileDelete: True
// .... .1.. = fileDirectory: True
// .... ..1. = unsolicitedStatus: True
// .... ...1 = informationReport: True
// 0... .... = eventNotification: False
// .0.. .... = attachToEventCondition: False
// ..0. .... = attachToSemaphore: False
// ...1 .... = conclude: True
// .... 1... = cancel: True
package main

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/slonegd/go61850"
	"github.com/slonegd/go61850/osi/cotp"
)

// proofOfConcept выполняет Proof of Concept: устанавливает COTP соединение,
// отправляет MMS Initiate Request и получает ответ.
func proofOfConcept(conn net.Conn, logger cotp.Logger) error {
	opts := []go61850.MmsClientOption{}
	if logger != nil {
		opts = append(opts, go61850.WithLogger(logger))
	}
	client := go61850.NewMmsClient(conn, opts...)

	ctx := context.Background()
	return client.Initiate(ctx)
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	address := "localhost:102"

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	log.Printf("Connected to %s\n", address)

	err = proofOfConcept(conn, nil)
	if err != nil {
		log.Fatalf("Proof of Concept failed: %v", err)
	}

	log.Println("Proof of Concept completed successfully")
}
