package actionssecurity

// triggerNames extracts the set of event names a workflow's `on:` block
// declares, handling all three legal shapes GitHub Actions allows: a bare
// string, a list of strings, or a map keyed by event name.
func triggerNames(on any) map[string]bool {
	names := map[string]bool{}
	switch v := on.(type) {
	case string:
		names[v] = true
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				names[s] = true
			}
		}
	case map[string]any:
		for k := range v {
			names[k] = true
		}
	}
	return names
}
