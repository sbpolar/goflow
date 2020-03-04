package netflow

import (
	"fmt"
	"strconv"
)

// FlowSetHeader contains fields shared by all Flow Sets (DataFlowSet,
// TemplateFlowSet, OptionsTemplateFlowSet).
type FlowSetHeader struct {
	// FlowSet ID:
	//    0 for TemplateFlowSet
	//    1 for OptionsTemplateFlowSet
	//    256-65535 for DataFlowSet (used as TemplateId)
	Id uint16

	// The total length of this FlowSet in bytes (including padding).
	Length uint16
}

// TemplateFlowSet is a collection of templates that describe structure of Data
// Records (actual NetFlow data).
type TemplateFlowSet struct {
	FlowSetHeader

	// List of Template Records
	Records []TemplateRecord
}

// DataFlowSet is a collection of Data Records (actual NetFlow data) and Options
// Data Records (meta data).
type DataFlowSet struct {
	FlowSetHeader

	Records []DataRecord
}

type OptionsDataFlowSet struct {
	FlowSetHeader

	Records []OptionsDataRecord
}

// TemplateRecord is a single template that describes structure of a Flow Record
// (actual Netflow data).
type TemplateRecord struct {
	// Each of the newly generated Template Records is given a unique
	// Template ID. This uniqueness is local to the Observation Domain that
	// generated the Template ID. Template IDs of Data FlowSets are numbered
	// from 256 to 65535.
	TemplateId uint16

	// Number of fields in this Template Record. Because a Template FlowSet
	// usually contains multiple Template Records, this field allows the
	// Collector to determine the end of the current Template Record and
	// the start of the next.
	FieldCount uint16

	// List of fields in this Template Record.
	Fields []interface{}
}

type DataRecord struct {
	Values []DataField
}

// OptionsDataRecord is meta data sent alongide actual NetFlow data. Combined
// with OptionsTemplateRecord it can be decoded to a single data row.
type OptionsDataRecord struct {
	// List of Scope values stored in raw format as []byte
	ScopesValues []DataField

	// List of Optons values stored in raw format as []byte
	OptionsValues []DataField
}

// Field describes type and length of a single value in a Flow Data Record.
// Field does not contain the record value itself it is just a description of
// what record value will look like.
type Field struct {
	// A numeric value that represents the type of field.
	Type uint16

	// The length (in bytes) of the field.
	Length uint16
}

type DataField struct {
	// A numeric value that represents the type of field.
	Type uint16

	// The value (in bytes) of the field.
	Value interface{}
	//Value []byte

	Length uint16
}

func (flowSet OptionsDataFlowSet) String(TypeToString func(uint16) string, ScopeToString func(uint16) string) string {
	str := fmt.Sprintf("       Id %v\n", flowSet.Id)
	str += fmt.Sprintf("       Length: %v\n", flowSet.Length)
	str += fmt.Sprintf("       Records (%v records):\n", len(flowSet.Records))

	for j, record := range flowSet.Records {
		str += fmt.Sprintf("       - Record %v:\n", j)
		str += fmt.Sprintf("            Scopes (%v):\n", len(record.ScopesValues))

		for k, value := range record.ScopesValues {
			str += fmt.Sprintf("            - %v. %v (%v): %v\n", k, ScopeToString(value.Type), value.Type, value.Value)
		}

		str += fmt.Sprintf("            Options (%v):\n", len(record.OptionsValues))

		for k, value := range record.OptionsValues {
			str += fmt.Sprintf("            - %v. %v (%v): %v\n", k, TypeToString(value.Type), value.Type, value.Value)
		}
	}

	return str
}

func (flowSet DataFlowSet) String(TypeToString func(uint16) string) string {
	str := fmt.Sprintf("       Id %v\n", flowSet.Id)
	str += fmt.Sprintf("       Length: %v\n", flowSet.Length)
	str += fmt.Sprintf("       Records (%v records):\n", len(flowSet.Records))

	for j, record := range flowSet.Records {
		str += fmt.Sprintf("       - Record %v:\n", j)
		str += fmt.Sprintf("            Values (%v):\n", len(record.Values))

		for k, value := range record.Values {
			str += fmt.Sprintf("            - %v. %v (%v): %v\n", k, TypeToString(value.Type), value.Type, value.Value)
		}
	}

	return str
}

func (flowSet TemplateFlowSet) String(TypeToString func(uint16) string) string {
	str := fmt.Sprintf("       Id %v\n", flowSet.Id)
	str += fmt.Sprintf("       Length: %v\n", flowSet.Length)
	str += fmt.Sprintf("       Records (%v records):\n", len(flowSet.Records))

	for j, record := range flowSet.Records {
		str += fmt.Sprintf("       - %v. Record:\n", j)
		str += fmt.Sprintf("            TemplateId: %v\n", record.TemplateId)
		str += fmt.Sprintf("            FieldCount: %v\n", record.FieldCount)
		str += fmt.Sprintf("            Fields (%v):\n", len(record.Fields))

		for k, tf := range record.Fields {
			switch field := tf.(type) {
			case Field:
				str += fmt.Sprintf("            - %v. %v (%v): %v\n", k, TypeToString(field.Type), field.Type, field.Length)
			case IPFIXTemplateField:
				entid := ""
				if field.EnterpriseID > 0 {
					entid = fmt.Sprintf(" (enterprise: %d)", field.EnterpriseID)
				}
				lengthStr := strconv.Itoa(int(field.Length))
				if field.Length == 0xFFFF {
					lengthStr = "VARIABLE"
				}
				str += fmt.Sprintf("            - %v. %v (%v): %s%s\n", k, TypeToString(field.Type), field.Type, lengthStr, entid)
			}
		}
	}

	return str
}
