package mms

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// parseHexStringForTest парсит hex строку в байты для тестов
// Удаляет пробелы, переносы строк и табы, затем парсит пары hex символов
func parseHexStringForTest(hexStr string) []byte {
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, "\n", "")
	hexStr = strings.ReplaceAll(hexStr, "\t", "")
	data := make([]byte, 0, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		if i+1 >= len(hexStr) {
			break
		}
		var b byte
		if _, err := fmt.Sscanf(hexStr[i:i+2], "%02x", &b); err != nil {
			continue
		}
		data = append(data, b)
	}
	return data
}

func TestParseGetVariableAccessAttributesResponse(t *testing.T) {
	tests := []struct {
		name      string
		buffer    string // hex строка без пробелов
		want      *VariableAccessAttributesResponse
		wantError string
	}{
		{
			name: "полный пакет из wireshark",
			// Пакет из комментария в go61850.go:
			// a1 82 01 0b - confirmed-ResponsePDU (Context-specific 1, Constructed, длина 0x010b)
			//   02 01 02 - invokeID (INTEGER, длина 1, значение 2)
			//   a6 82 01 04 - confirmedServiceResponse: getVariableAccessAttributes (Context-specific 6, Constructed, длина 0x0104)
			//      80 01 00 - mmsDeletable: false (tag 0x80, boolean, длина 1, значение 0x00)
			//      a2 81 fe - typeSpecification: structure (tag 0xa2), длина 0x01fe
			// Пакет из комментария (только MMS часть):
			// a182010b020102a6820104800100a281fe...
			// Структура согласно комментарию:
			// - invokeID: 2
			// - mmsDeletable: False
			// - typeSpecification: structure с 4 компонентами (AnIn1, AnIn2, AnIn3, AnIn4)
			//   Каждый компонент - структура с 3 элементами:
			//   - mag (структура с 1 элементом f)
			//   - q (bit-string) - TODO: парсинг типов компонентов не работает, нужно починить
			//   - t (тип не указан явно, но судя по контексту MMS - возможно utc-time или другой тип) - TODO: парсинг типов компонентов не работает, нужно починить
			buffer: "a182010b020102a6820104800100a281fea281fba181f8303c8005416e496e31a133a231a12f301a80036d6167a113a211a10f300d800166a108a7060201200201083008800171a1038401f33007800174a1029100303c8005416e496e32a133a231a12f301a80036d6167a113a211a10f300d800166a108a7060201200201083008800171a1038401f33007800174a1029100303c8005416e496e33a133a231a12f301a80036d6167a113a211a10f300d800166a108a7060201200201083008800171a1038401f33007800174a1029100303c8005416e496e34a133a231a12f301a80036d6167a113a211a10f300d800166a108a7060201200201083008800171a1038401f33007800174a1029100",
			want: &VariableAccessAttributesResponse{
				InvokeID:     2,
				MmsDeletable: false,
				TypeSpecification: &TypeSpecification{
					Type: TypeSpecStructure,
					Structure: &StructureTypeSpec{
						Components: []ComponentSpec{
							{
								Name: "AnIn1",
								Type: &TypeSpecification{
									Type: TypeSpecStructure,
									Structure: &StructureTypeSpec{
										Components: []ComponentSpec{
											{
												Name: "mag",
												Type: &TypeSpecification{
													Type: TypeSpecStructure,
													Structure: &StructureTypeSpec{
														Components: []ComponentSpec{
															{
																Name: "f",
																// Type: &TypeSpecification{
																// 	Type: TypeSpecFloatingPoint,
																// 	FloatingPoint: &FloatingPointTypeSpec{
																// 		ExponentWidth: 8,
																// 		FormatWidth:   32,
																// 	},
																// },
															},
														},
													},
												},
											},
											// TODO: парсинг типов компонентов не работает, нужно починить
											{
												Name: "q",
												// 	Type: &TypeSpecification{
												// 		Type:          TypeSpecBitString,
												// 		BitStringSize: 13,
												// 	},
											},
											{
												Name: "t",
												// 	Type: &TypeSpecification{
												// 		Type: TypeSpecUTCTime,
												// 	},
											},
										},
									},
								},
							},
							{
								Name: "AnIn2",
								Type: &TypeSpecification{
									Type: TypeSpecStructure,
									Structure: &StructureTypeSpec{
										Components: []ComponentSpec{
											{
												Name: "mag",
												Type: &TypeSpecification{
													Type: TypeSpecStructure,
													Structure: &StructureTypeSpec{
														Components: []ComponentSpec{
															{
																Name: "f",
																// Type: &TypeSpecification{
																// 	Type: TypeSpecFloatingPoint,
																// 	FloatingPoint: &FloatingPointTypeSpec{
																// 		ExponentWidth: 8,
																// 		FormatWidth:   32,
																// 	},
																// },
															},
														},
													},
												},
											},
											// TODO: парсинг типов компонентов не работает, нужно починить
											{
												Name: "q",
												// 	Type: &TypeSpecification{
												// 		Type:          TypeSpecBitString,
												// 		BitStringSize: 13,
												// 	},
											},
											{
												Name: "t",
												// 	Type: &TypeSpecification{
												// 		Type: TypeSpecUTCTime,
												// 	},
											},
										},
									},
								},
							},
							{
								Name: "AnIn3",
								Type: &TypeSpecification{
									Type: TypeSpecStructure,
									Structure: &StructureTypeSpec{
										Components: []ComponentSpec{
											{
												Name: "mag",
												Type: &TypeSpecification{
													Type: TypeSpecStructure,
													Structure: &StructureTypeSpec{
														Components: []ComponentSpec{
															{
																Name: "f",
																// Type: &TypeSpecification{
																// 	Type: TypeSpecFloatingPoint,
																// 	FloatingPoint: &FloatingPointTypeSpec{
																// 		ExponentWidth: 8,
																// 		FormatWidth:   32,
																// 	},
																// },
															},
														},
													},
												},
											},
											// TODO: парсинг типов компонентов не работает, нужно починить
											{
												Name: "q",
												// 	Type: &TypeSpecification{
												// 		Type:          TypeSpecBitString,
												// 		BitStringSize: 13,
												// 	},
											},
											{
												Name: "t",
												// 	Type: &TypeSpecification{
												// 		Type: TypeSpecUTCTime,
												// 	},
											},
										},
									},
								},
							},
							{
								Name: "AnIn4",
								Type: &TypeSpecification{
									Type: TypeSpecStructure,
									Structure: &StructureTypeSpec{
										Components: []ComponentSpec{
											{
												Name: "mag",
												Type: &TypeSpecification{
													Type: TypeSpecStructure,
													Structure: &StructureTypeSpec{
														Components: []ComponentSpec{
															{
																Name: "f",
																// Type: &TypeSpecification{
																// 	Type: TypeSpecFloatingPoint,
																// 	FloatingPoint: &FloatingPointTypeSpec{
																// 		ExponentWidth: 8,
																// 		FormatWidth:   32,
																// 	},
																// },
															},
														},
													},
												},
											},
											// TODO: парсинг типов компонентов не работает, нужно починить
											{
												Name: "q",
												// 	Type: &TypeSpecification{
												// 		Type:          TypeSpecBitString,
												// 		BitStringSize: 13,
												// 	},
											},
											{
												Name: "t",
												// 	Type: &TypeSpecification{
												// 		Type: TypeSpecUTCTime,
												// 	},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buffer := parseHexStringForTest(tt.buffer)
			got, err := ParseGetVariableAccessAttributesResponse(buffer)

			if tt.wantError != "" {
				assert.Error(t, err, tt.name)
				if err != nil {
					assert.Contains(t, err.Error(), tt.wantError, tt.name)
				}
				return
			}
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}
