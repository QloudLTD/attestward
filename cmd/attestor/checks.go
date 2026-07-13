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

	"github.com/sioakim/ssdf/internal/collect"
	"github.com/sioakim/ssdf/internal/mapping"
	"github.com/sioakim/ssdf/mappings"
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

// MatrixRow is one row of `attestor checks list`'s output — the contract
// issue #30's generated checks-reference docs build on, so field names are
// meant to stay stable.
type MatrixRow struct {
	CheckID    string      `json:"check_id" yaml:"check_id"`
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
// not registered is "unimplemented"; registered but not referenced by any
// mapping task is "unmapped". Rows are sorted by check ID for deterministic
// output.
func buildMatrix(ssdf *mapping.SSDFMapping, cisa *mapping.CISAMapping, registered []collect.CheckMeta) []MatrixRow {
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

	metaByID := map[string]collect.CheckMeta{}
	for _, meta := range registered {
		metaByID[meta.ID] = meta
	}

	ids := map[string]struct{}{}
	for id := range tasksByCheck {
		ids[id] = struct{}{}
	}
	for id := range metaByID {
		ids[id] = struct{}{}
	}

	rows := make([]MatrixRow, 0, len(ids))
	for id := range ids {
		tasks := append([]string{}, tasksByCheck[id]...)
		sort.Strings(tasks)

		clusterSet := map[string]struct{}{}
		for _, taskID := range tasks {
			for _, clusterID := range clustersByTask[taskID] {
				clusterSet[clusterID] = struct{}{}
			}
		}
		clusters := make([]string, 0, len(clusterSet))
		for c := range clusterSet {
			clusters = append(clusters, c)
		}
		sort.Strings(clusters)

		_, inMapping := tasksByCheck[id]
		meta, inRegistry := metaByID[id]

		row := MatrixRow{CheckID: id, SSDFTasks: tasks, Clusters: clusters}
		switch {
		case inRegistry && inMapping:
			row.Status = statusOK
		case inMapping:
			row.Status = statusUnimplemented
		default:
			row.Status = statusUnmapped
		}
		if inRegistry {
			row.Title = meta.Title
			row.Collector = meta.Collector
			row.TokenScope = meta.TokenScope
		}
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].CheckID < rows[j].CheckID })
	return rows
}

func renderChecksTable(w io.Writer, rows []MatrixRow) error {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "CHECK ID\tTITLE\tCOLLECTOR\tSSDF TASKS\tCLUSTERS\tTOKEN SCOPE\tSTATUS"); err != nil {
		return err
	}
	for _, r := range rows {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.CheckID, r.Title, r.Collector, strings.Join(r.SSDFTasks, ","), strings.Join(r.Clusters, ","), r.TokenScope, r.Status); err != nil {
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

	rows := buildMatrix(ssdf, cisa, collect.Registered())
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
