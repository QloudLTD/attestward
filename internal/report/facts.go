package report

import (
	"encoding/json"
	"sort"
)

// factScalar is one Facts entry whose value is a single scalar (string,
// number, bool) — rendered as a plain "key: value" line.
type factScalar struct {
	Key   string
	Value any
}

// factTable is one Facts entry shaped like a table: a list of
// same-ish-shaped objects (e.g. C05/C06/C07's "per_release" rows, C08's
// finding lists — every one of them is exactly this shape). Columns is
// the union of every row's keys, sorted, so heterogeneous rows still get
// one consistent header rather than one column set per row.
type factTable struct {
	Key     string
	Columns []string
	Rows    [][]any
}

// factList is one Facts entry shaped like a plain list of scalars (not
// objects) — rendered as a comma/bullet list rather than a table.
type factList struct {
	Key   string
	Items []any
}

// factsView is Facts (map[string]any) reclassified into the three shapes
// the templates know how to render, sorted by key within each shape so
// output is deterministic regardless of Go's randomized map iteration.
type factsView struct {
	Scalars []factScalar
	Tables  []factTable
	Lists   []factList
}

func buildFactsView(facts map[string]any) factsView {
	var fv factsView
	keys := make([]string, 0, len(facts))
	for k := range facts {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := facts[k]
		rows, isTable := asTableRows(v)
		switch {
		case isTable:
			columns := unionColumns(rows)
			fv.Tables = append(fv.Tables, factTable{Key: k, Columns: columns, Rows: toTableRows(rows, columns)})
		default:
			if items, isList := asScalarList(v); isList {
				fv.Lists = append(fv.Lists, factList{Key: k, Items: items})
				continue
			}
			fv.Scalars = append(fv.Scalars, factScalar{Key: k, Value: v})
		}
	}
	return fv
}

// asTableRows recognizes a Facts value shaped like a list of objects,
// handling both the literal Go type collectors construct in-memory
// ([]map[string]any) and the shape a JSON-decoded pack yields instead
// ([]any of map[string]any — json.Unmarshal never produces []map[string]any
// directly), since this package must render both a freshly-built pack and
// one round-tripped through evidence.json (issue #28's future job).
func asTableRows(v any) ([]map[string]any, bool) {
	switch val := v.(type) {
	case []map[string]any:
		if len(val) == 0 {
			return nil, false
		}
		return val, true
	case []any:
		if len(val) == 0 {
			return nil, false
		}
		rows := make([]map[string]any, 0, len(val))
		for _, item := range val {
			m, ok := item.(map[string]any)
			if !ok {
				return nil, false
			}
			rows = append(rows, m)
		}
		return rows, true
	default:
		return nil, false
	}
}

// asScalarList recognizes a Facts value shaped like a plain list of
// non-object values (e.g. []string) — anything that fails asTableRows'
// "every element is an object" test but is still some slice type. An
// empty slice is deliberately still classified as a (zero-item) list
// here, not left to fall through to fmtFactValue's scalar path: without
// this, an empty []string/[]any fact (e.g. C08's third_party_unpinned
// when nothing is unpinned) would render as the raw JSON literal "[]"
// instead of the templates' "(none)" list-empty case.
func asScalarList(v any) ([]any, bool) {
	switch val := v.(type) {
	case []string:
		items := make([]any, len(val))
		for i, s := range val {
			items[i] = s
		}
		return items, true
	case []any:
		return val, true
	default:
		return nil, false
	}
}

func unionColumns(rows []map[string]any) []string {
	set := map[string]bool{}
	for _, row := range rows {
		for k := range row {
			set[k] = true
		}
	}
	columns := make([]string, 0, len(set))
	for k := range set {
		columns = append(columns, k)
	}
	sort.Strings(columns)
	return columns
}

func toTableRows(rows []map[string]any, columns []string) [][]any {
	out := make([][]any, 0, len(rows))
	for _, row := range rows {
		values := make([]any, len(columns))
		for i, col := range columns {
			values[i] = row[col]
		}
		out = append(out, values)
	}
	return out
}

// fmtFactValue renders any single Facts value (scalar, or a value inside
// a table row / list that wasn't itself further classified) as plain
// text — nil as empty, bools/numbers/strings naturally, anything else
// (a nested object the generic classifier didn't unpack) as compact JSON
// rather than Go's %v syntax, since that's what an API-derived value
// most likely originated as anyway.
func fmtFactValue(v any) string {
	switch val := v.(type) {
	case nil:
		return ""
	case string:
		return val
	case bool:
		if val {
			return "true"
		}
		return "false"
	case float64, int, int64:
		raw, err := json.Marshal(val)
		if err != nil {
			return ""
		}
		return string(raw)
	default:
		raw, err := json.Marshal(val)
		if err != nil {
			return ""
		}
		return string(raw)
	}
}
