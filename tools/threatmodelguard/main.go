// threatmodelguard is a CI guard for issue #260 (usage: `go run
// ./tools/threatmodelguard`): flags any self-hosted-macOS job whose name
// isn't backtick-quoted in docs/threat-model.md's "Shared, persistent
// runner state" bullet. See scan.go's doc comment for the precision this
// accepts and why. Also covers issue #274's collector-list check — see
// collectors.go's doc comment.
package main

import (
	"fmt"
	"os"
)

func main() {
	failed := false

	missing, err := run(".github/workflows", "docs/threat-model.md")
	if err != nil {
		fmt.Fprintln(os.Stderr, "threatmodelguard: "+err.Error())
		os.Exit(2)
	}
	if len(missing) > 0 {
		failed = true
		fmt.Fprintln(os.Stderr, "threatmodelguard: docs/threat-model.md's \"Shared, persistent runner state\" "+
			"bullet doesn't name these self-hosted macOS jobs (issue #260):")
		for _, name := range missing {
			fmt.Fprintf(os.Stderr, "  - %s\n", name)
		}
		fmt.Fprintln(os.Stderr, "\nAdd each to that bullet, backtick-quoted, or confirm it's genuinely not "+
			"self-hosted macOS and fix the workflow/guard instead.")
	}

	missingCollectors, err := runADOCollectors("internal/collect/azuredevops", "docs/threat-model.md")
	if err != nil {
		fmt.Fprintln(os.Stderr, "threatmodelguard: "+err.Error())
		os.Exit(2)
	}
	if len(missingCollectors) > 0 {
		failed = true
		fmt.Fprintln(os.Stderr, "threatmodelguard: docs/threat-model.md's \"ten ADO collector packages\" "+
			"list doesn't name these internal/collect/azuredevops packages (issue #274):")
		for _, name := range missingCollectors {
			fmt.Fprintf(os.Stderr, "  - %s\n", name)
		}
		fmt.Fprintln(os.Stderr, "\nAdd each to that list, or confirm it genuinely has no Collect(ctx...) "+
			"method and fix the package/guard instead.")
	}

	if failed {
		os.Exit(1)
	}
}

// run does the actual scan and returns what's missing — it never calls
// os.Exit itself, so it's directly testable without exec'ing a
// subprocess (mirrors tools/rubricguard's identically-shaped run).
func run(workflowsDir, threatModelPath string) ([]string, error) {
	jobNames, err := selfHostedMacOSJobs(workflowsDir)
	if err != nil {
		return nil, fmt.Errorf("scan workflows: %w", err)
	}
	doc, err := os.ReadFile(threatModelPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", threatModelPath, err)
	}
	section, err := runnerStateSection(doc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", threatModelPath, err)
	}
	return missingFromDoc(jobNames, section), nil
}
