package cotp

import (
	"encoding/hex"
	"reflect"
	"testing"
)

// parseHexString парсит hex строку в []byte
func parseHexString(s string) []byte {
	// Удаляем пробелы
	cleaned := ""
	for _, r := range s {
		if r != ' ' {
			cleaned += string(r)
		}
	}
	data, err := hex.DecodeString(cleaned)
	if err != nil {
		panic(err)
	}
	return data
}

func TestParseTPKT(t *testing.T) {
	tests := []struct {
		name    string
		hexStr  string
		want    *TPKT
		wantErr bool
	}{
		{
			name:   "Packet1_ConnectionConfirm",
			hexStr: "03 00 00 16 11 d0 00 01 00 01 00 c0 01 0d c2 02 00 01 c1 02 00 01",
			want: &TPKT{
				Version:  0x03,
				Reserved: 0x00,
				Length:   22,
				Data:     parseHexString("11 d0 00 01 00 01 00 c0 01 0d c2 02 00 01 c1 02 00 01"),
			},
			wantErr: false,
		},
		{
			name:   "Packet2_DataTPDU",
			hexStr: "03 00 00 8f 02 f0 80 0e 86 05 06 13 01 00 16 01 02 14 02 00 02 34 02 00 01 c1 74 31 72 a0 03 80 01 01 a2 6b 83 04 00 00 00 01 a5 12 30 07 80 01 00 81 02 51 01 30 07 80 01 00 81 02 51 01 61 4f 30 4d 02 01 01 a0 48 61 46 a1 07 06 05 28 ca 22 02 03 a2 03 02 01 00 a3 05 a1 03 02 01 00 be 2f 28 2d 02 01 03 a0 28 a9 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 00 02 00 00 40 ed 18",
			want: &TPKT{
				Version:  0x03,
				Reserved: 0x00,
				Length:   143,
				Data:     parseHexString("02 f0 80 0e 86 05 06 13 01 00 16 01 02 14 02 00 02 34 02 00 01 c1 74 31 72 a0 03 80 01 01 a2 6b 83 04 00 00 00 01 a5 12 30 07 80 01 00 81 02 51 01 30 07 80 01 00 81 02 51 01 61 4f 30 4d 02 01 01 a0 48 61 46 a1 07 06 05 28 ca 22 02 03 a2 03 02 01 00 a3 05 a1 03 02 01 00 be 2f 28 2d 02 01 03 a0 28 a9 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 00 02 00 00 40 ed 18"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := parseHexString(tt.hexStr)
			got, err := ParseTPKT(data)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTPKT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			if got.Version != tt.want.Version {
				t.Errorf("ParseTPKT() Version = 0x%02x, want 0x%02x", got.Version, tt.want.Version)
			}

			if got.Reserved != tt.want.Reserved {
				t.Errorf("ParseTPKT() Reserved = 0x%02x, want 0x%02x", got.Reserved, tt.want.Reserved)
			}

			if got.Length != tt.want.Length {
				t.Errorf("ParseTPKT() Length = %d, want %d", got.Length, tt.want.Length)
			}

			if !reflect.DeepEqual(got.Data, tt.want.Data) {
				t.Errorf("ParseTPKT() Data = %v, want %v", got.Data, tt.want.Data)
			}
		})
	}
}

func TestParseCOTP(t *testing.T) {
	tests := []struct {
		name    string
		hexStr  string
		want    *COTP
		wantErr bool
	}{
		{
			name:   "Packet1_ConnectionConfirm",
			hexStr: "11 d0 00 01 00 01 00 c0 01 0d c2 02 00 01 c1 02 00 01",
			want: &COTP{
				Length:             0x11,                      // Length: 17
				Type:               COTPTypeConnectionConfirm, // PDU Type: CC Connect Confirm (0x0d)
				DestRef:            0x0001,                    // Destination reference: 0x0001
				SrcRef:             0x0001,                    // Source reference: 0x0001
				Class:              0,                         // 0000 .... = Class: 0 (из байта ProtocolClass)
				ExtendedFormats:    false,                     // .... ..0. = Extended formats: False (из байта ProtocolClass)
				NoExplicitFlowCtrl: false,                     // .... ...0 = No explicit flow control: False (из байта ProtocolClass)
				ProtocolClass:      0x00,                      // Protocol class: 0x00
				TpduSize:           0x0d,                      // TPDU size: 8192
				DstTSAP:            parseHexString("00 01"),   // Destination TSAP: 0001
				SrcTSAP:            parseHexString("00 01"),   // Source TSAP: 0001
				Data:               []byte{},
			},
			wantErr: false,
		},
		{
			name:   "Packet2_DataTPDU",
			hexStr: "02 f0 80 0e 86 05 06 13 01 00 16 01 02 14 02 00 02 34 02 00 01 c1 74 31 72 a0 03 80 01 01 a2 6b 83 04 00 00 00 01 a5 12 30 07 80 01 00 81 02 51 01 30 07 80 01 00 81 02 51 01 61 4f 30 4d 02 01 01 a0 48 61 46 a1 07 06 05 28 ca 22 02 03 a2 03 02 01 00 a3 05 a1 03 02 01 00 be 2f 28 2d 02 01 03 a0 28 a9 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 00 02 00 00 40 ed 18",
			want: &COTP{
				Length:         0x02,
				Type:           COTPTypeData,
				Flags:          0x80,
				IsLastDataUnit: true,
				Data:           parseHexString("0e 86 05 06 13 01 00 16 01 02 14 02 00 02 34 02 00 01 c1 74 31 72 a0 03 80 01 01 a2 6b 83 04 00 00 00 01 a5 12 30 07 80 01 00 81 02 51 01 30 07 80 01 00 81 02 51 01 61 4f 30 4d 02 01 01 a0 48 61 46 a1 07 06 05 28 ca 22 02 03 a2 03 02 01 00 a3 05 a1 03 02 01 00 be 2f 28 2d 02 01 03 a0 28 a9 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 00 02 00 00 40 ed 18"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := parseHexString(tt.hexStr)
			got, err := ParseCOTP(data)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCOTP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			if got.Length != tt.want.Length {
				t.Errorf("ParseCOTP() Length = 0x%02x, want 0x%02x", got.Length, tt.want.Length)
			}

			if got.Type != tt.want.Type {
				t.Errorf("ParseCOTP() Type = 0x%02x, want 0x%02x", got.Type, tt.want.Type)
			}

			if got.Flags != tt.want.Flags {
				t.Errorf("ParseCOTP() Flags = 0x%02x, want 0x%02x", got.Flags, tt.want.Flags)
			}

			if got.IsLastDataUnit != tt.want.IsLastDataUnit {
				t.Errorf("ParseCOTP() IsLastDataUnit = %v, want %v", got.IsLastDataUnit, tt.want.IsLastDataUnit)
			}

			if got.DestRef != tt.want.DestRef {
				t.Errorf("ParseCOTP() DestRef = 0x%04x, want 0x%04x", got.DestRef, tt.want.DestRef)
			}

			if got.SrcRef != tt.want.SrcRef {
				t.Errorf("ParseCOTP() SrcRef = 0x%04x, want 0x%04x", got.SrcRef, tt.want.SrcRef)
			}

			if got.Class != tt.want.Class {
				t.Errorf("ParseCOTP() Class = %d, want %d", got.Class, tt.want.Class)
			}

			if got.ExtendedFormats != tt.want.ExtendedFormats {
				t.Errorf("ParseCOTP() ExtendedFormats = %v, want %v", got.ExtendedFormats, tt.want.ExtendedFormats)
			}

			if got.NoExplicitFlowCtrl != tt.want.NoExplicitFlowCtrl {
				t.Errorf("ParseCOTP() NoExplicitFlowCtrl = %v, want %v", got.NoExplicitFlowCtrl, tt.want.NoExplicitFlowCtrl)
			}

			if got.ProtocolClass != tt.want.ProtocolClass {
				t.Errorf("ParseCOTP() ProtocolClass = 0x%02x, want 0x%02x", got.ProtocolClass, tt.want.ProtocolClass)
			}

			if got.TpduSize != tt.want.TpduSize {
				t.Errorf("ParseCOTP() TpduSize = 0x%02x, want 0x%02x", got.TpduSize, tt.want.TpduSize)
			}

			if !reflect.DeepEqual(got.DstTSAP, tt.want.DstTSAP) {
				t.Errorf("ParseCOTP() DstTSAP = %v, want %v", got.DstTSAP, tt.want.DstTSAP)
			}

			if !reflect.DeepEqual(got.SrcTSAP, tt.want.SrcTSAP) {
				t.Errorf("ParseCOTP() SrcTSAP = %v, want %v", got.SrcTSAP, tt.want.SrcTSAP)
			}

			if !reflect.DeepEqual(got.Data, tt.want.Data) {
				t.Errorf("ParseCOTP() Data = %v, want %v", got.Data, tt.want.Data)
			}
		})
	}
}
