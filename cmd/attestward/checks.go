package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/mappings"
)

// checkStatus is a matrix row's implementation status: whether a check
// exists in both the mapping data and the collector registry. This is
// distinct from model.Status, which describes a single check's runtime
// scan result — checkStatus describes the state of the codebase itself.
type checkStatus string

const (
	statusOK            checkStatus = "ok"
	statusUnimplemented checkStatus = "unimplemented" // referenced by a mapping task but no registered collector
	statusUnmapped      checkStatus = "unmapped"      // registered but not referenced by any mapping task
)

// MatrixRow is one row of `attestward checks list`'s output — the contract
// issue #30's generated checks-reference docs build on, so field names are
// meant to stay stable. Platform is empty for an "unimplemented" row (a
// check referenced by a mapping task but registered under no platform at
// all — there's no platform to attribute) and for self-attestation
// questions (platform-agnostic by design); every other row names exactly
// one platform, since the same check ID registered under two platforms
// (issue #34's check-identity model) is two separate rows, not one merged
// row — unlike docs/checks-reference.md's narrative rendering
// (internal/checksref), which merges them into one heading with
// per-platform subsections, this is a flat matrix where "one row per
// (platform, check)" is the more useful shape.
type MatrixRow struct {
	CheckID    string      `json:"check_id" yaml:"check_id"`
	Platform   string      `json:"platform,omitempty" yaml:"platform,omitempty"`
	Title      string      `json:"title" yaml:"title"`
	Collector  string      `json:"collector" yaml:"collector"`
	SSDFTasks  []string    `json:"ssdf_tasks" yaml:"ssdf_tasks"`
	Clusters   []string    `json:"clusters" yaml:"clusters"`
	TokenScope string      `json:"token_scope" yaml:"token_scope"`
	Status     checkStatus `json:"status" yaml:"status"`
}

// buildMatrix cross-references the registered collector checks against the
// checks referenced by ssdf's tasks — no hardcoded duplication of either
// side. A check present in both is "ok"; referenced by a mapping task but
// not registered under any platform is "unimplemented"; registered under a
// platform but not referenced by any mapping task is "unmapped" (evaluated
// per platform — the same ID could in principle be unmapped under one
// platform and fine under another, though nothing produces that today).
// saQuestions are handled separately (see below) rather than folded into
// that same three-way judgment: unlike a collector check, a
// self-attestation question's own existence in the embedded questions file
// *is* its complete implementation — there's no second "is it registered in
// a Go collector" half to be missing, so "unimplemented" can never apply,
// and a question with no ssdf_tasks (dev-security-training,
// agency-notification-process — no task in this project's
// deliberately-scoped 31-task subset fits either) is a legitimate,
// deliberate design choice, not the same kind of gap "unmapped" flags for a
// stray collector check. Rows are sorted by check ID then platform for
// deterministic output — platform only breaks ties, so a single-platform
// registry (every check as of this writing) sorts identically to before
// this field existed.
func buildMatrix(ssdf *mapping.SSDFMapping, cisa *mapping.CISAMapping, registered []collect.CheckMeta, saQuestions []mapping.SelfAttestationQuestion) []MatrixRow {
	tasksByCheck := map[string][]string{}
	for _, task := range ssdf.Tasks {
		for _, checkID := range task.Checks {
			tasksByCheck[checkID] = append(tasksByCheck[checkID], task.ID)
		}
	}

	clustersByTask := map[string][]string{}
	for _, cluster := range cisa.Clusters {
		for _, taskID := range cluster.SSDFTasks {
			clustersByTask[taskID] = append(clustersByTask[taskID], cluster.ID)
		}
	}

	tasksAndClustersFor := func(checkID string) (tasks, clusters []string) {
		tasks = append([]string{}, tasksByCheck[checkID]...)
		sort.Strings(tasks)
		clusterSet := map[string]struct{}{}
		for _, taskID := range tasks {
			for _, clusterID := range clustersByTask[taskID] {
				clusterSet[clusterID] = struct{}{}
			}
		}
		clusters = make([]string, 0, len(clusterSet))
		for c := range clusterSet {
			clusters = append(clusters, c)
		}
		sort.Strings(clusters)
		return tasks, clusters
	}

	saIDs := map[string]bool{}
	for _, q := range saQuestions {
		saIDs[q.ID] = true
	}

	// checkKey is (platform, id) — the registry's own identity (issue
	// #148/#164's review): an ID-only map here would let a second
	// platform's registration silently overwrite the first's Title/
	// Collector/TokenScope in this row.
	type checkKey struct{ Platform, ID string }
	metaByKey := map[checkKey]collect.CheckMeta{}
	registeredIDs := map[string]bool{} // every ID registered under at least one platform
	for _, meta := range registered {
		platform := collect.NormalizePlatform(meta.Platform)
		metaByKey[checkKey{platform, meta.ID}] = meta
		registeredIDs[meta.ID] = true
	}

	rows := make([]MatrixRow, 0, len(metaByKey)+len(saQuestions))

	for key, meta := range metaByKey {
		tasks, clusters := tasksAndClustersFor(key.ID)
		_, inMapping := tasksByCheck[key.ID]

		row := MatrixRow{
			CheckID: key.ID, Platform: key.Platform, SSDFTasks: tasks, Clusters: clusters,
			Title: meta.Title, Collector: meta.Collector, TokenScope: meta.TokenScope,
		}
		if inMapping {
			row.Status = statusOK
		} else {
			row.Status = statusUnmapped
		}
		rows = append(rows, row)
	}

	for id := range tasksByCheck {
		if saIDs[id] || registeredIDs[id] {
			continue
		}
		tasks, clusters := tasksAndClustersFor(id)
		rows = append(rows, MatrixRow{CheckID: id, SSDFTasks: tasks, Clusters: clusters, Status: statusUnimplemented})
	}

	for _, q := range saQuestions {
		tasks, clusters := tasksAndClustersFor(q.ID)
		rows = append(rows, MatrixRow{
			CheckID:    q.ID,
			Title:      q.Question,
			Collector:  "self-attestation",
			SSDFTasks:  tasks,
			Clusters:   clusters,
			TokenScope: "none — self-attested, not platform-verified",
			Status:     statusOK,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CheckID != rows[j].CheckID {
			return rows[i].CheckID < rows[j].CheckID
		}
		return rows[i].Platform < rows[j].Platform
	})
	return rows
}

func renderChecksTable(w io.Writer, rows []MatrixRow) error {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "CHECK ID\tPLATFORM\tTITLE\tCOLLECTOR\tSSDF TASKS\tCLUSTERS\tTOKEN SCOPE\tSTATUS"); err != nil {
		return err
	}
	for _, r := range rows {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.CheckID, r.Platform, r.Title, r.Collector, strings.Join(r.SSDFTasks, ","), strings.Join(r.Clusters, ","), r.TokenScope, r.Status); err != nil {
			return err
		}
	}
	return tw.Flush()
}

var (
	checksFormat string
	checksStrict bool
)

var checksCmd = &cobra.Command{
	Use:   "checks",
	Short: "Inspect the verification check matrix",
}

var checksListCmd = &cobra.Command{
	Use:   "list",
	Short: "List every check: collector, SSDF tasks, form cluster, and token permission",
	RunE:  runChecksList,
}

func init() {
	checksListCmd.Flags().StringVar(&checksFormat, "format", "table", "output format: table, json, or yaml")
	checksListCmd.Flags().BoolVar(&checksStrict, "strict", false, "exit nonzero if any check is unimplemented or unmapped")
	checksCmd.AddCommand(checksListCmd)
	rootCmd.AddCommand(checksCmd)
}

func runChecksList(cmd *cobra.Command, _ []string) error {
	ssdf, err := mapping.LoadSSDFFS(mappings.FS, "ssdf-800-218.yaml")
	if err != nil {
		return fmt.Errorf("load ssdf mapping: %w", err)
	}
	cisa, err := mapping.LoadCISAFS(mappings.FS, "cisa-ssda-form.yaml", ssdf)
	if err != nil {
		return fmt.Errorf("load cisa mapping: %w", err)
	}
	saQuestions, err := mapping.LoadSelfAttestationQuestionsFS(mappings.FS, "self-attestation-questions.yaml", ssdf)
	if err != nil {
		return fmt.Errorf("load self-attestation questions: %w", err)
	}

	rows := buildMatrix(ssdf, cisa, collect.Registered(), saQuestions.Questions)
	out := cmd.OutOrStdout()

	switch checksFormat {
	case "table":
		if err := renderChecksTable(out, rows); err != nil {
			return err
		}
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			return err
		}
	case "yaml":
		enc := yaml.NewEncoder(out)
		if err := enc.Encode(rows); err != nil {
			return err
		}
		if err := enc.Close(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown --format %q (want table, json, or yaml)", checksFormat)
	}

	if checksStrict {
		for _, r := range rows {
			if r.Status != statusOK {
				return fmt.Errorf("--strict: check %s is %s", r.CheckID, r.Status)
			}
		}
	}
	return nil
}
