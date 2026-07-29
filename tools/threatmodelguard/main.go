// threatmodelguard is a CI guard (usage: `go run ./tools/threatmodelguard`)
// that keeps docs/threat-model.md's machine-checkable enumerations honest.
//
// It checks the "ADO collector packages" list in both directions (issue
// #274, and #302 for the reverse): every package under
// internal/collect/azuredevops exposing a Collect(ctx...) method must be
// named in the list, and every name in the list must correspond to such a
// package. See collectors.go's doc comment for how that list is anchored.
//
// It previously also guarded the "Shared, persistent runner state" bullet's
// enumeration of self-hosted macOS jobs (issues #260, #286, #302). That check
// was removed when the repo went public (issue #138) and every self-hosted
// runner was deregistered: with no self-hosted job left in any workflow it had
// nothing to compare against, and its expected list was pure drift waiting to
// happen. The threat-model section it guarded was rewritten in the same change
// to describe ephemeral GitHub-hosted runners — so the residual risk that
// enumeration existed to bound is retired, not merely left unguarded.
package main

import (
	"fmt"
	"os"
)

func main() {
	failed := false

	missingCollectors, extraCollectors, err := runADOCollectors("internal/collect/azuredevops", "docs/threat-model.md")
	if err != nil {
		fmt.Fprintln(os.Stderr, "threatmodelguard: "+err.Error())
		os.Exit(2)
	}
	if len(missingCollectors) > 0 {
		failed = true
		fmt.Fprintln(os.Stderr, "threatmodelguard: docs/threat-model.md's \"ADO collector packages\" "+
			"list doesn't name these internal/collect/azuredevops packages (issue #274):")
		for _, name := range missingCollectors {
			fmt.Fprintf(os.Stderr, "  - %s\n", name)
		}
		fmt.Fprintln(os.Stderr, "\nAdd each to that list, or confirm it genuinely has no Collect(ctx...) "+
			"method and fix the package/guard instead.")
	}
	if len(extraCollectors) > 0 {
		failed = true
		fmt.Fprintln(os.Stderr, "threatmodelguard: docs/threat-model.md's \"ADO collector packages\" "+
			"list names these packages, but none exist under internal/collect/azuredevops with a "+
			"Collect(ctx...) method (issue #302):")
		for _, name := range extraCollectors {
			fmt.Fprintf(os.Stderr, "  - %s\n", name)
		}
		fmt.Fprintln(os.Stderr, "\nRemove each from that list, or confirm the package genuinely exists "+
			"and fix the package/guard instead.")
	}

	if failed {
		os.Exit(1)
	}
}
