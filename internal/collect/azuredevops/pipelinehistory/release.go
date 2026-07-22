package pipelinehistory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/sioakim/attestward/internal/collect/azuredevops"
)

// ReleaseInfo is the minimal release data the linkage/lookback algorithms
// need — mirrors runhistory.ReleaseInfo's exact shape (TagName, CommitSHA,
// PublishedAt), deliberately decoupled from any Azure DevOps API type so
// this package's pure functions stay testable without constructing REST
// response shapes.
type ReleaseInfo struct {
	TagName     string
	CommitSHA   string
	PublishedAt time.Time
}

// gitRef is the subset of Azure DevOps's GitRef shape (Git Refs - List)
// ResolveReleases needs. PeeledObjectID is populated only for an annotated
// tag (peelTags=true on the request) — its presence is exactly how an
// annotated tag is told apart from a lightweight one here: ObjectID is the
// tag object's own SHA for an annotated tag, or the commit SHA directly
// for a lightweight one, and PeeledObjectID (present only for the
// annotated case) is the commit the tag object itself points to.
type gitRef struct {
	Name           string `json:"name"`
	ObjectID       string `json:"objectId"`
	PeeledObjectID string `json:"peeledObjectId"`
}

// gitUserDate mirrors Azure DevOps's GitUserDate shape — used by both the
// annotated-tag object's taggedBy field and a commit's author/committer
// fields, all three of the same shape.
type gitUserDate struct {
	Date adoDate `json:"date"`
}

// adoDateNoTZLayout is the timezone-less date-time form the Annotated Tags
// - Get reference's own sample response shows ("2017-06-22T04:28:23", no
// "Z"/offset) — Go's default RFC3339 decode (what encoding/json uses for a
// plain time.Time) rejects that form outright. [fixture-verify]: it's
// unconfirmed whether a real Azure DevOps response actually omits the
// timezone or the docs sample is simply an abbreviated example: this is
// exactly the kind of discrepancy the S9 recorded-response verification
// pass should confirm one way or the other. Until then, adoDate decodes
// both forms so a real response either way doesn't silently fail — a
// timezone-less value is treated as UTC.
const adoDateNoTZLayout = "2006-01-02T15:04:05"

// adoDate is a time.Time that decodes Azure DevOps date-time strings
// leniently — see adoDateNoTZLayout's doc comment for why.
type adoDate struct {
	time.Time
}

func (d *adoDate) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("pipelinehistory: decode date: %w", err)
	}
	if s == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		d.Time = t
		return nil
	}
	t, err := time.ParseInLocation(adoDateNoTZLayout, s, time.UTC)
	if err != nil {
		return fmt.Errorf("pipelinehistory: parse date %q: matches neither RFC3339 nor the timezone-less form: %w", s, err)
	}
	d.Time = t
	return nil
}

// annotatedTagRaw is the subset of GitAnnotatedTag (Git Annotated Tags -
// Get) this package needs: the tagger's date.
type annotatedTagRaw struct {
	TaggedBy gitUserDate `json:"taggedBy"`
}

// commitRaw is the subset of GitCommit (Git Commits - Get) this package
// needs: the committer's date — used for a lightweight tag, which (unlike
// an annotated tag) has no tag object of its own to carry a date, only the
// commit it points straight at. Committer (not author) is used
// deliberately: it's the date the change actually entered this
// repository's history, the closest analogue to what a GitHub Release's
// PublishedAt captures — an author date can predate a rebase/cherry-pick
// by an arbitrary amount.
type commitRaw struct {
	Committer gitUserDate `json:"committer"`
}

// listTags lists every tag ref in repositoryID via GET
// .../refs?filter=tags/&peelTags=true — peelTags populates PeeledObjectID
// for annotated tags, the only way to tell an annotated tag from a
// lightweight one from this response alone (see gitRef's doc comment).
func listTags(ctx context.Context, client *azuredevops.Client, project, repositoryID string) ([]gitRef, error) {
	path := fmt.Sprintf("/%s/%s/_apis/git/repositories/%s/refs", client.Org(), project, repositoryID)
	query := url.Values{
		"filter":      {"tags/"},
		"peelTags":    {"true"},
		"api-version": {"7.1"},
	}
	var refs []gitRef
	if err := azuredevops.GetJSON(ctx, client, azuredevops.HostCore, path, query, &refs); err != nil {
		return nil, err
	}
	return refs, nil
}

// annotatedTagDate resolves an annotated tag's own date via GET
// .../annotatedtags/{objectId} — objectId is the tag OBJECT's SHA (a
// gitRef's ObjectID field for an annotated tag), not the commit it points
// to (PeeledObjectID).
func annotatedTagDate(ctx context.Context, client *azuredevops.Client, project, repositoryID, tagObjectID string) (time.Time, error) {
	path := fmt.Sprintf("/%s/%s/_apis/git/repositories/%s/annotatedtags/%s", client.Org(), project, repositoryID, tagObjectID)
	query := url.Values{"api-version": {"7.1"}}
	var tag annotatedTagRaw
	if err := azuredevops.GetJSONObject(ctx, client, azuredevops.HostCore, path, query, &tag); err != nil {
		return time.Time{}, err
	}
	return tag.TaggedBy.Date.Time, nil
}

// commitDate resolves a commit's committer date via GET
// .../commits/{commitId} — used for a lightweight tag, whose ObjectID
// already IS the commit SHA directly (no separate tag object exists to
// resolve first).
func commitDate(ctx context.Context, client *azuredevops.Client, project, repositoryID, commitID string) (time.Time, error) {
	path := fmt.Sprintf("/%s/%s/_apis/git/repositories/%s/commits/%s", client.Org(), project, repositoryID, commitID)
	query := url.Values{"api-version": {"7.1"}}
	var commit commitRaw
	if err := azuredevops.GetJSONObject(ctx, client, azuredevops.HostCore, path, query, &commit); err != nil {
		return time.Time{}, err
	}
	return commit.Committer.Date.Time, nil
}

// tagRefPrefix is the ref-name prefix every tag ref carries, stripped to
// recover the bare tag name filepath.Match compares against tagPattern —
// mirrors runhistory's use of GitHub's already-bare release TagName field,
// which Azure DevOps's ref-based model has no equivalent of.
const tagRefPrefix = "refs/tags/"

// ResolveReleases lists every tag ref in repositoryID, resolves each one
// matching tagPattern (filepath.Match syntax, e.g. the default "v*" — same
// glob semantics as runhistory.FilterReleasesInLookback, not a regex) to a
// ReleaseInfo, and reports how many matching tags could not be resolved.
//
// This bundles listing + per-tag resolution into one function, unlike
// runhistory's split (FetchReleases lists, ResolveReleaseCommit resolves
// one tag, and the caller in sasthistory.go loops + counts drops itself) —
// deliberately: Azure DevOps's tag API never gives a tag's date for free
// the way GitHub's Releases API does (a GitHub Release object already
// carries PublishedAt before any resolution is attempted at all), so
// determining ANY release's date here always requires the extra
// annotated-tag-or-commit follow-up call this function makes internally.
// Bundling that multi-step assembly into one well-tested unit, rather than
// asking every future ADO collector (C05, C06, C07) to reimplement the
// same annotated-vs-lightweight branching, is the more sensible split for
// this platform specifically.
//
// dropped names every tagPattern-matching tag whose date resolution
// failed, UNCONDITIONALLY — a deliberate, documented divergence from
// sasthistory.go's droppedTags, which only COUNTS a drop when the
// release's (already-known) PublishedAt falls within the lookback window.
// That refinement depends on knowing PublishedAt BEFORE attempting
// resolution, which is exactly what Azure DevOps's tag API cannot provide:
// when date resolution itself is what failed, there is no independent date
// to judge window membership against. A tag that doesn't match tagPattern
// at all is never a drop, same rule as the GitHub side.
//
// Because that same window-gating is unavailable here, dropped returns
// tag NAMES, not a bare count: the names are what lets a future caller
// recover the information GitHub's window gate would otherwise have
// provided (which specific tags to worry about), and a caller applying its
// own window logic afterward can still narrow further.
//
// A caller (the C05/C06 collector PRs, #150-#154) porting sasthistory.go's
// "any dropped tag caps the check at partial" rule verbatim from the
// GitHub side should do so deliberately, not by default: since dropped is
// unconditional here (not already window-filtered the way the GitHub
// caller's own droppedTags is), applying that rule as-is will trigger on
// more tags than the equivalent GitHub check would — it will read
// stricter/noisier on Azure DevOps for the same underlying repository
// history, purely because of this platform difference, not because ADO
// pipelines are actually less reliable. That tradeoff is exactly what
// those future PRs need to weigh, not something this package should
// silently decide on their behalf.
func ResolveReleases(ctx context.Context, client *azuredevops.Client, project, repositoryID, tagPattern string) (releases []ReleaseInfo, dropped []string, err error) {
	refs, err := listTags(ctx, client, project, repositoryID)
	if err != nil {
		return nil, nil, err
	}

	for _, ref := range refs {
		tagName := strings.TrimPrefix(ref.Name, tagRefPrefix)
		if ok, matchErr := filepath.Match(tagPattern, tagName); matchErr != nil || !ok {
			continue // out of scope regardless of resolution outcome — not a drop, same rule as runhistory
		}

		var (
			commitSHA string
			date      time.Time
			dateErr   error
		)
		if ref.PeeledObjectID != "" {
			commitSHA = ref.PeeledObjectID
			date, dateErr = annotatedTagDate(ctx, client, project, repositoryID, ref.ObjectID)
			if dateErr != nil {
				// The annotated-tag object's own date lookup failed, but
				// the peeled commit SHA is already in hand from the refs
				// listing — fall back to that commit's own date rather
				// than dropping a tag we can otherwise fully identify.
				date, dateErr = commitDate(ctx, client, project, repositoryID, ref.PeeledObjectID)
			}
		} else {
			commitSHA = ref.ObjectID
			date, dateErr = commitDate(ctx, client, project, repositoryID, ref.ObjectID)
		}
		if dateErr != nil {
			dropped = append(dropped, tagName)
			continue
		}

		releases = append(releases, ReleaseInfo{TagName: tagName, CommitSHA: commitSHA, PublishedAt: date})
	}

	return releases, dropped, nil
}
