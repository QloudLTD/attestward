package checksref

import (
	"bytes"
	"embed"
	"fmt"
	"sort"
	texttemplate "text/template"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/internal/model"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

// rubricOrder controls rubric-row display order within a check's section —
// worst-first, matching internal/report's own status ordering so the
// vocabulary reads the same across every document this tool generates.
// StatusSelfAttested is deliberately absent: no C01-C10 check's Rubric can
// contain it (self-attestation questions don't register a CheckMeta at
// all — see collect.CheckMeta's own doc comment), so including it here
// would just be dead code.
var rubricOrder = []model.Status{
	model.StatusVerifiedFail,
	model.StatusPartial,
	model.StatusNotCheckable,
	model.StatusVerifiedPass,
}

// context is everything the template needs, precomputed once by
// buildContext — same "no lookups/branching in template text" discipline
// internal/report's renderContext uses.
type context struct {
	SSDF MappingCitation
	CISA MappingCitation

	Groups []collectorGroup

	SAQuestions []saQuestionView
}

// MappingCitation is the deterministic, source-derived stand-in for a
// generation timestamp: which version of which mapping this reference was
// built from, and when that mapping's own source was retrieved (both
// already recorded in the YAML itself). A wall-clock "generated at" value
// was considered and rejected — see DECISIONS.md's entry for issue #30 —
// because it would make two consecutive `attestward checks docs` runs over
// identical input produce different bytes, defeating the CI drift check's
// whole purpose.
type MappingCitation struct {
	Version   string
	Retrieved string
	SourceURL string
}

type collectorGroup struct {
	CollectorID string
	Checks      []checkView
}

// checkView is one check ID's section. Tasks/Clusters are shared across
// platforms — SSDF/CISA mapping data has no platform concept, so a check ID
// cites the same tasks/clusters no matter which platform(s) implement it.
// Everything else (title, token permission, endpoints, rubric, remediation,
// fixture) is platform-specific and lives in Platforms — one entry for a
// single-platform check (every check as of this writing), more than one
// once a second platform registers the same ID (issue #34's check-identity
// model: same ID, per-platform everything else). The template renders a
// single platform's fields inline with no platform label when there's only
// one (today's exact output), and a labeled subsection per platform
// otherwise.
type checkView struct {
	ID        string
	Tasks     []taskView
	Clusters  []string
	Platforms []checkPlatformView
}

// checkPlatformView is one platform's rendering of a check — the fields
// the checklist for issue #148's per-platform subsections names explicitly:
// token permission, endpoints, rubric, remediation, fixture (plus Title,
// which the epic's own design also treats as per-platform, e.g. a
// GitHub-product-named ID keeping its ID with a different Title on ADO).
type checkPlatformView struct {
	Platform    string
	Title       string
	TokenScope  string
	Remediation string
	FixtureRef  string
	Endpoints   []string
	Rubric      []rubricRow
}

type rubricRow struct {
	Status model.Status
	Text   string
}

type taskView struct {
	ID           string
	PracticeID   string
	PracticeText string
	Text         string
}

type saQuestionView struct {
	ID       string
	Question string
	Tasks    []taskView
	Clusters []string
}

// githubAnchor reproduces GitHub's markdown heading-to-anchor algorithm
// closely enough for this template's own heading text (ASCII letters,
// digits, spaces, `.`, `-`): lowercase, drop anything that isn't a letter,
// digit, space, or hyphen, then turn spaces into hyphens. GitHub's real
// algorithm has more edge cases this doesn't reproduce — it keeps
// underscores (this function drops them) and de-duplicates repeated
// headings with a `-1`/`-2` suffix — neither of which this template's
// fixed heading set (collector IDs are letters/digits/`.`/`-` only, and
// unique) ever triggers, so a full implementation isn't needed.
func githubAnchor(heading string) string {
	var b []byte
	for _, r := range heading {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b = append(b, byte(r))
		case r >= 'A' && r <= 'Z':
			b = append(b, byte(r-'A'+'a'))
		case r == ' ':
			b = append(b, '-')
		case r == '-':
			b = append(b, '-')
		}
	}
	return string(b)
}

// Render builds docs/checks-reference.md from already-loaded mapping data
// and an already-collected registry snapshot — a pure function of its
// inputs, no I/O, matching internal/report's renderer contract. registered
// would normally come from collect.Registered() (called by the caller,
// same seam internal/report/poam.go's RenderPOAM doc comment explains: this
// package must never import a platform collector package directly).
//
// Render fails loudly rather than emitting a blank section if any
// registered check is missing Rubric, FixtureRef, or Remediation — issue
// #30's acceptance criterion ("generator fails on missing metadata rather
// than emitting blanks"). Endpoints is deliberately NOT checked here: it
// may legitimately be empty for a check whose result is a fixed fact
// rather than an API-derived one (see collect.CheckMeta.Endpoints's own
// doc comment).
func Render(registered []collect.CheckMeta, ssdf *mapping.SSDFMapping, cisa *mapping.CISAMapping, saQuestions *mapping.SelfAttestationQuestions) ([]byte, error) {
	ctx, err := buildContext(registered, ssdf, cisa, saQuestions)
	if err != nil {
		return nil, err
	}

	tmpl, err := texttemplate.New("checks-reference.md.tmpl").Funcs(texttemplate.FuncMap{
		"anchor": githubAnchor,
	}).ParseFS(templatesFS, "templates/checks-reference.md.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse checks-reference.md template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return nil, fmt.Errorf("render checks-reference.md: %w", err)
	}
	return buf.Bytes(), nil
}

func buildContext(registered []collect.CheckMeta, ssdf *mapping.SSDFMapping, cisa *mapping.CISAMapping, saQuestions *mapping.SelfAttestationQuestions) (context, error) {
	ctx := context{
		SSDF: MappingCitation{Version: ssdf.Version, Retrieved: ssdf.Retrieved, SourceURL: ssdf.Source.URL},
		CISA: MappingCitation{Version: cisa.Version, Retrieved: cisa.Retrieved, SourceURL: cisa.Source.URL},
	}

	tasksByCheck, clustersByTask := taskAndClusterIndexes(ssdf, cisa)
	tasksAndClustersFor := func(checkID string) ([]taskView, []string) {
		return tasksAndClusters(checkID, tasksByCheck, clustersByTask, ssdf)
	}

	// Group by Collector, then by check ID: the same ID can be registered
	// under more than one platform (issue #34's check-identity model), and
	// must render as one heading with a per-platform subsection each — two
	// platforms silently producing two separate headings for what a reader
	// should see as one check would be worse than the last-write-wins bug
	// this replaces (found in review of #164).
	byCollectorThenID := map[string]map[string][]collect.CheckMeta{}
	for _, meta := range registered {
		if byCollectorThenID[meta.Collector] == nil {
			byCollectorThenID[meta.Collector] = map[string][]collect.CheckMeta{}
		}
		byCollectorThenID[meta.Collector][meta.ID] = append(byCollectorThenID[meta.Collector][meta.ID], meta)
	}

	groupByCollector := map[string][]checkView{}
	for collectorID, byID := range byCollectorThenID {
		ids := make([]string, 0, len(byID))
		for id := range byID {
			ids = append(ids, id)
		}
		sort.Strings(ids)

		for _, id := range ids {
			metas := append([]collect.CheckMeta{}, byID[id]...)
			sort.Slice(metas, func(i, j int) bool {
				return collect.NormalizePlatform(metas[i].Platform) < collect.NormalizePlatform(metas[j].Platform)
			})

			tasks, clusters := tasksAndClustersFor(id)
			cv := checkView{ID: id, Tasks: tasks, Clusters: clusters}
			for _, meta := range metas {
				if err := requireCompleteMeta(meta); err != nil {
					return context{}, err
				}
				rubric, err := rubricRows(meta.ID, meta.Rubric)
				if err != nil {
					return context{}, err
				}
				cv.Platforms = append(cv.Platforms, checkPlatformView{
					Platform:    collect.NormalizePlatform(meta.Platform),
					Title:       meta.Title,
					TokenScope:  meta.TokenScope,
					Remediation: meta.Remediation,
					FixtureRef:  meta.FixtureRef,
					Endpoints:   meta.Endpoints,
					Rubric:      rubric,
				})
			}
			groupByCollector[collectorID] = append(groupByCollector[collectorID], cv)
		}
	}

	collectorIDs := make([]string, 0, len(groupByCollector))
	for id := range groupByCollector {
		collectorIDs = append(collectorIDs, id)
	}
	sort.Strings(collectorIDs)
	for _, id := range collectorIDs {
		ctx.Groups = append(ctx.Groups, collectorGroup{CollectorID: id, Checks: groupByCollector[id]})
	}

	if saQuestions != nil {
		questions := append([]mapping.SelfAttestationQuestion{}, saQuestions.Questions...)
		sort.Slice(questions, func(i, j int) bool { return questions[i].ID < questions[j].ID })
		for _, q := range questions {
			tasks, clusters := tasksAndClustersFor(q.ID)
			ctx.SAQuestions = append(ctx.SAQuestions, saQuestionView{ID: q.ID, Question: q.Question, Tasks: tasks, Clusters: clusters})
		}
	}

	return ctx, nil
}

// requireCompleteMeta is issue #30's "fails loudly, not blanks" criterion,
// applied per platform instance now that the same check ID can carry more
// than one CheckMeta (issue #34's check-identity model): every platform
// registering a check must independently supply Rubric/FixtureRef/
// Remediation/Title/TokenScope, not just whichever platform happens to be
// checked first. Endpoints is deliberately NOT checked here: it may
// legitimately be empty for a check whose result is a fixed fact rather
// than an API-derived one (see collect.CheckMeta.Endpoints's own doc
// comment).
func requireCompleteMeta(meta collect.CheckMeta) error {
	if len(meta.Rubric) == 0 {
		return fmt.Errorf("checksref: check %s has no Rubric registered — every check must document what each status it can produce means before the reference can be generated", meta.ID)
	}
	if meta.FixtureRef == "" {
		return fmt.Errorf("checksref: check %s has no FixtureRef registered", meta.ID)
	}
	if meta.Remediation == "" {
		return fmt.Errorf("checksref: check %s has no Remediation registered", meta.ID)
	}
	if meta.Title == "" {
		return fmt.Errorf("checksref: check %s has no Title registered", meta.ID)
	}
	if meta.TokenScope == "" {
		return fmt.Errorf("checksref: check %s has no TokenScope registered", meta.ID)
	}
	return nil
}

// rubricRows orders rubric's entries per rubricOrder. It errors rather than
// silently dropping a row if rubric contains a status rubricOrder doesn't
// know about — without this check, a status this renderer has no display
// order for would just vanish from the check's section, the exact kind of
// silent gap issue #30's "fails loudly, not blanks" criterion exists to
// catch (found in review of this PR).
func rubricRows(checkID string, rubric map[model.Status]string) ([]rubricRow, error) {
	rows := make([]rubricRow, 0, len(rubric))
	for _, s := range rubricOrder {
		if text, ok := rubric[s]; ok {
			rows = append(rows, rubricRow{Status: s, Text: text})
		}
	}
	if len(rows) != len(rubric) {
		return nil, fmt.Errorf("checksref: check %s's Rubric has a status rubricOrder doesn't know how to display — every status a check's Rubric documents must appear in rubricOrder or it would silently vanish from the reference", checkID)
	}
	return rows, nil
}

// taskAndClusterIndexes builds the same check->tasks and task->clusters
// indexes cmd/attestward's buildMatrix does, kept as a local, unexported
// helper here rather than shared: buildMatrix lives in package main, which
// nothing under internal/ can import.
func taskAndClusterIndexes(ssdf *mapping.SSDFMapping, cisa *mapping.CISAMapping) (tasksByCheck map[string][]string, clustersByTask map[string][]string) {
	tasksByCheck = map[string][]string{}
	for _, task := range ssdf.Tasks {
		for _, checkID := range task.Checks {
			tasksByCheck[checkID] = append(tasksByCheck[checkID], task.ID)
		}
	}
	clustersByTask = map[string][]string{}
	for _, cluster := range cisa.Clusters {
		for _, taskID := range cluster.SSDFTasks {
			clustersByTask[taskID] = append(clustersByTask[taskID], cluster.ID)
		}
	}
	return tasksByCheck, clustersByTask
}

func tasksAndClusters(checkID string, tasksByCheck, clustersByTask map[string][]string, ssdf *mapping.SSDFMapping) ([]taskView, []string) {
	taskIDs := append([]string{}, tasksByCheck[checkID]...)
	sort.Strings(taskIDs)

	tasks := make([]taskView, 0, len(taskIDs))
	clusterSet := map[string]struct{}{}
	for _, taskID := range taskIDs {
		tv := taskView{ID: taskID}
		if task, ok := ssdf.TaskByID[taskID]; ok {
			tv.Text = task.Text
			tv.PracticeID = task.Practice
			if practice, ok := ssdf.Practices[task.Practice]; ok {
				tv.PracticeText = practice.Title
			}
		}
		tasks = append(tasks, tv)
		for _, clusterID := range clustersByTask[taskID] {
			clusterSet[clusterID] = struct{}{}
		}
	}

	clusters := make([]string, 0, len(clusterSet))
	for c := range clusterSet {
		clusters = append(clusters, c)
	}
	sort.Strings(clusters)

	return tasks, clusters
}
