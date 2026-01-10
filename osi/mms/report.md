# Структура IEC 61850 Report в MMS InformationReport

## Общая структура

IEC 61850 Report передаётся через MMS как `unconfirmedPDU` с типом `informationReport`. 

```
MMS unconfirmed-PDU
└── unconfirmedService: informationReport
    ├── variableAccessSpecification
    │   └── variableListName: "RPT"  ← Маркер типа (не rptId!)
    └── listOfAccessResult: массив элементов
```

**Важно**: `variableListName = "RPT"` - это маркер типа, указывающий, что это IEC 61850 report. Сам `rptId` находится в первом элементе `listOfAccessResult`.

## Этапы подписки на report

### 1. Установка соединения
```c
IedConnection con = IedConnection_create();
IedConnection_connect(con, &error, hostname, tcpPort);
```

### 2. Регистрация обработчика report'ов
```c
IedConnection_installReportHandler(con, "simpleIOGenericIO/LLN0.RP.EventsRCB01", 
                                   rptId, reportCallbackFunction, parameter);
```

Внутри библиотека регистрирует callback для обработки асинхронных report'ов через `MmsConnection_setInformationReportHandler`.

### 3. Чтение и настройка RCB (Report Control Block)
```c
ClientReportControlBlock rcb = IedConnection_getRCBValues(con, &error, 
    "simpleIOGenericIO/LLN0.RP.EventsRCB01", NULL);

ClientReportControlBlock_setResv(rcb, true);  // Резервируем RCB
ClientReportControlBlock_setTrgOps(rcb, TRG_OPT_DATA_CHANGED | ...);  // Триггеры
ClientReportControlBlock_setDataSetReference(rcb, "simpleIOGenericIO/LLN0$Events");
ClientReportControlBlock_setRptEna(rcb, true);  // Включаем report
```

### 4. Активация подписки
```c
IedConnection_setRCBValues(con, &error, rcb, 
    RCB_ELEMENT_RESV | RCB_ELEMENT_DATSET | RCB_ELEMENT_TRG_OPS | 
    RCB_ELEMENT_RPT_ENA | RCB_ELEMENT_GI, true);
```

Отправляется MMS Write к серверу для записи параметров RCB, сервер активирует report.

## Различие между синхронными ответами и асинхронными report'ами

### Синхронные ответы (confirmedResponsePDU)
- **Тип PDU**: `MmsPdu_PR_confirmedResponsePdu`
- **Имеют invokeID**: связываются с запросом через `invokeID`
- **Обработка**: Клиент сопоставляет `invokeID` с ожидающим запросом из таблицы `outstandingCalls`

### Асинхронные report'ы (unconfirmedPDU)
- **Тип PDU**: `MmsPdu_PR_unconfirmedPDU`
- **НЕ имеют invokeID**: это unconfirmed сообщения
- **Обработка**: Маршрутизируются через отдельный обработчик `informationReportHandler`

При получении InformationReport:
1. Извлекается `rptId` из первого элемента `listOfAccessResult[0]`
2. Ищется зарегистрированный обработчик по `rptId` в списке `enabledReports`
3. Если найден, парсятся данные и вызывается callback

## Структура listOfAccessResult в report

Пример структуры из реального report (15 элементов):

### Element [0]: rptId (Report ID)
```
AccessResult: success (1)
  success: visible-string (10)
    visible-string: Events1
```
**Назначение**: Идентификатор report'а, используемый для маршрутизации к правильному обработчику.

---

### Element [1]: OptFlds (Optional Fields) - битовая маска
```
AccessResult: success (1)
  success: bit-string (4)
    Padding: 6
    bit-string: 7880
```

**Назначение**: Определяет, какие опциональные поля присутствуют в report.

**Биты OptFlds** (проверяются начиная с индекса 1, бит 0 зарезервирован):
- Бит 1 (seqNum): включено = sequence number присутствует
- Бит 2 (timestamp): включено = timestamp присутствует
- Бит 3 (reasonForInclusion): включено = reason for inclusion присутствует
- Бит 4 (datSet): включено = dataset name присутствует
- Бит 5 (dataReference): включено = data reference для каждого элемента
- Бит 6 (bufOvfl): включено = buffer overflow flag присутствует
- Бит 7 (entryId): включено = entry ID присутствует
- Бит 8 (confRev): включено = configuration revision присутствует
- Бит 9 (segmentation): включено = segmentation fields присутствуют

**Пример расшифровки "7880"** (в hex, padding 6 означает используется 26 бит из 32):
- Бит 1 (seqNum): ✓ включено
- Бит 2 (timestamp): ✓ включено
- Бит 3 (reasonForInclusion): ✓ включено
- Бит 4 (datSet): ✓ включено
- Бит 8 (confRev): ✓ включено

---

### Element [2]: Sequence Number
```
AccessResult: success (1)
  success: unsigned (6)
    unsigned: 0
```
**Назначение**: Порядковый номер report'а. Увеличивается с каждым отправленным report'ом.

---

### Element [3]: Timestamp
```
AccessResult: success (1)
  success: binary-time (12)
    binary-time: Jan 10, 2026 04:06:11.628000000 UTC
```
**Назначение**: Время создания report'а на сервере в формате UTC.

---

### Element [4]: DataSet Name
```
AccessResult: success (1)
  success: visible-string (10)
    visible-string: simpleIOGenericIO/LLN0$Events
```
**Назначение**: Имя dataset'а, из которого берутся данные. Обратите внимание на символ "$" вместо "." - это стандартное MMS представление.

---

### Element [5]: Configuration Revision
```
AccessResult: success (1)
  success: unsigned (6)
    unsigned: 1
```
**Назначение**: Версия конфигурации dataset'а. Изменяется при модификации состава dataset'а.

---

### Element [6]: Inclusion Bitstring
```
AccessResult: success (1)
  success: bit-string (4)
    Padding: 4
    bit-string: f0
```

**Назначение**: Битовая маска, определяющая какие элементы dataset'а включены в report.

**Расшифровка "f0"** (padding 4, используется 4 бита):
- dataset[0]: 1 ✓ **ВКЛЮЧЕН** (бит установлен)
- dataset[1]: 1 ✓ **ВКЛЮЧЕН**
- dataset[2]: 1 ✓ **ВКЛЮЧЕН**
- dataset[3]: 1 ✓ **ВКЛЮЧЕН**

Все 4 элемента dataset'а включены в report.

---

### Elements [7-N]: Значения элементов dataset

После inclusion bitstring идут **значения включенных элементов dataset** в порядке их следования в inclusion bitstring.

Если включено 4 элемента, то будет 4 значения:
```
[7]  значение dataset[0]
[8]  значение dataset[1]
[9]  значение dataset[2]
[10] значение dataset[3]
```

Типы значений могут быть различными: boolean, integer, float, структуры и т.д.

**Пример из реального report**:
```
[7]  boolean: False  ← значение dataset[0]
[8]  boolean: False  ← значение dataset[1]
[9]  boolean: False  ← значение dataset[2]
[10] boolean: False  ← значение dataset[3]
```

**Примечание**: Если в OptFlds установлен бит 5 (dataReference), то перед значениями идут data references для каждого включенного элемента.

---

### Elements [N+1-M]: Reason-for-Inclusion

Если в OptFlds установлен бит 3 (reasonForInclusion), то после всех значений идут reason-for-inclusion для каждого включенного элемента.

Каждый reason-for-inclusion представляет собой bitstring, определяющий причину включения:

**Биты reason-for-inclusion**:
- Бит 0 (reserved): зарезервирован
- Бит 1 (data-change): изменение значения данных
- Бит 2 (quality-change): изменение качества
- Бит 3 (data-update): обновление данных
- Бит 4 (integrity): integrity report
- Бит 5 (GI): General Interrogation

**Пример из реального report**:
```
[11] bit-string: 04  ← reason для dataset[0] (padding 2, 6 бит)
[12] bit-string: 04  ← reason для dataset[1]
[13] bit-string: 04  ← reason для dataset[2]
[14] bit-string: 04  ← reason для dataset[3]
```

Расшифровка "04":
- Бит 5 (GI): 1 ✓ - включение по причине General Interrogation

Все элементы включены по причине **GI (General Interrogation)** - это означает, что report был запрошен клиентом через триггер GI, и в ответ пришли все текущие значения из dataset'а.

## Как определить какие переменные пришли в report

### Способ 1: Через dataset directory (рекомендуемый)

При подписке на report клиент должен прочитать dataset directory:

```c
LinkedList dataSetDirectory = IedConnection_getDataSetDirectory(con, &error, 
    "simpleIOGenericIO/LLN0.Events", NULL);
```

Этот список содержит имена всех элементов dataset'а в порядке их следования:
- `dataset[0]` = первое имя из directory
- `dataset[1]` = второе имя из directory
- `dataset[2]` = третье имя из directory
- `dataset[3]` = четвертое имя из directory

В callback функции используйте этот directory для получения имён переменных:

```c
void reportCallbackFunction(void* parameter, ClientReport report)
{
    LinkedList dataSetDirectory = (LinkedList) parameter;
    MmsValue* dataSetValues = ClientReport_getDataSetValues(report);
    
    for (int i = 0; i < LinkedList_size(dataSetDirectory); i++) {
        ReasonForInclusion reason = ClientReport_getReasonForInclusion(report, i);
        
        if (reason != IEC61850_REASON_NOT_INCLUDED) {
            LinkedList entry = LinkedList_get(dataSetDirectory, i);
            char* entryName = (char*) entry->data;  // Имя переменной
            
            MmsValue* value = MmsValue_getElement(dataSetValues, i);  // Значение
            // ... обработка
        }
    }
}
```

### Способ 2: Через inclusion bitstring

Inclusion bitstring (element [6]) показывает, какие индексы dataset включены:
- Если бит `i` = 1, то `dataset[i]` включен
- Если бит `i` = 0, то `dataset[i]` не включен

В примере: "f0" = все 4 бита установлены (1111), значит включены элементы [0], [1], [2], [3].

### Способ 3: Через ClientReport API

Библиотека предоставляет удобные функции для работы с report:

```c
// Получить все значения dataset
MmsValue* dataSetValues = ClientReport_getDataSetValues(report);

// Получить reason для конкретного элемента
ReasonForInclusion reason = ClientReport_getReasonForInclusion(report, elementIndex);

// Получить имя dataset'а
const char* dataSetName = ClientReport_getDataSetName(report);
```

## Пример полной структуры report

```
listOfAccessResult: 15 items

[0]  rptId: "Events1"  (visible-string)
[1]  optFlds: "7880"   (bit-string) → включены: seqNum, timestamp, reason, datSet, confRev
[2]  seqNum: 0         (unsigned)
[3]  timestamp: ...    (binary-time)
[4]  datSet: "simpleIOGenericIO/LLN0$Events"  (visible-string)
[5]  confRev: 1        (unsigned)
[6]  inclusion: "f0"   (bit-string) → все 4 элемента включены [0,1,2,3]
[7]  dataset[0] значение: boolean False
[8]  dataset[1] значение: boolean False
[9]  dataset[2] значение: boolean False
[10] dataset[3] значение: boolean False
[11] dataset[0] reason: "04" (bit-string) → GI
[12] dataset[1] reason: "04" (bit-string) → GI
[13] dataset[2] reason: "04" (bit-string) → GI
[14] dataset[3] reason: "04" (bit-string) → GI
```

## Примечания

1. **Порядок элементов**: Опциональные поля идут в определённом порядке согласно OptFlds. Если поле выключено, оно пропускается.

2. **Data Reference**: Если OptFlds[5] = dataReference включен, то перед значениями идут data references (visible-string) для каждого включенного элемента.

3. **Segmentation**: Если OptFlds[9] = segmentation включен, то после confRev идут subSeqNum и moreSegmentsFollow.

4. **Buffer Overflow**: Если OptFlds[6] = bufOvfl включен, то после datSet идёт boolean флаг переполнения буфера.

5. **Entry ID**: Если OptFlds[7] = entryId включен, то после bufOvfl идёт octet-string с entry ID (для buffered report'ов).

6. **Reason-for-Inclusion**: Идёт после всех значений и только для включенных элементов (в порядке включения).

## См. также

- `c/src/iec61850/client/client_report.c` - парсинг report'ов на клиенте
- `c/src/iec61850/server/mms_mapping/reporting.c` - формирование report'ов на сервере
- `c/src/iec61850/client/ied_connection.c` - обработка InformationReport на уровне MMS

