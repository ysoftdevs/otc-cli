package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ysoftdevs/otc-cli/formats"
	"github.com/ysoftdevs/otc-cli/services/iam"
)

func iamColumn(label, key string) formats.Column[iam.Record] {
	return formats.Col(label, func(record iam.Record) string { return iamValue(record[key], false) })
}

func iamUsersView() formats.View[iam.Record] {
	return formats.View[iam.Record]{Columns: []formats.Column[iam.Record]{
		iamColumn("ID", "id"), iamColumn("Name", "name"), iamColumn("Domain ID", "domain_id"), iamColumn("Enabled", "enabled"),
	}}
}

func iamGroupsView() formats.View[iam.Record] {
	return formats.View[iam.Record]{Columns: []formats.Column[iam.Record]{
		iamColumn("ID", "id"), iamColumn("Name", "name"), iamColumn("Domain ID", "domain_id"), iamColumn("Description", "description"),
	}}
}

func iamRolesView() formats.View[iam.Record] {
	return formats.View[iam.Record]{Columns: []formats.Column[iam.Record]{
		iamColumn("ID", "id"), iamColumn("Name", "name"), iamColumn("Display Name", "display_name"),
		iamColumn("Type", "type"), iamColumn("Description", "description"),
	}}
}

func iamProvidersView() formats.View[iam.Record] {
	return formats.View[iam.Record]{Columns: []formats.Column[iam.Record]{
		iamColumn("ID", "id"), iamColumn("Enabled", "enabled"), iamColumn("SSO Type", "sso_type"),
		iamColumn("Remote IDs", "remote_ids"), iamColumn("Description", "description"),
	}}
}

func iamProtocolsView() formats.View[iam.Record] {
	return formats.View[iam.Record]{Columns: []formats.Column[iam.Record]{
		iamColumn("ID", "id"), iamColumn("Mapping ID", "mapping_id"),
	}}
}

func iamMappingsView() formats.View[iam.Record] {
	return formats.View[iam.Record]{Columns: []formats.Column[iam.Record]{
		iamColumn("ID", "id"),
		formats.Col("Rules", func(record iam.Record) string {
			rules, ok := record["rules"].([]any)
			if !ok {
				return ""
			}
			return fmt.Sprint(len(rules))
		}),
	}}
}

// JSON/YAML always receive the untouched records, including policy Conditions,
// Resources and federation rule extensions. Only the table view is flattened.
func printIAMRecords(rows []iam.Record, view formats.View[iam.Record], detail bool) error {
	if !detail || (format != "" && format != "table") {
		return formats.PrintFormatted(format, rows, view)
	}
	type field struct{ Name, Value string }
	fields := make([]field, 0)
	for _, row := range rows {
		keys := make([]string, 0, len(row))
		for key := range row {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fields = append(fields, field{key, iamValue(row[key], true)})
		}
	}
	return formats.PrintFormatted(format, fields, formats.View[field]{Columns: []formats.Column[field]{
		formats.Col("Field", func(f field) string { return f.Name }),
		formats.Col("Value", func(f field) string { return f.Value }),
	}})
}

func iamValue(value any, indent bool) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	var data []byte
	var err error
	if indent {
		data, err = json.MarshalIndent(value, "", "  ")
	} else {
		data, err = json.Marshal(value)
	}
	if err != nil {
		return fmt.Sprint(value)
	}
	return strings.TrimSpace(string(data))
}
