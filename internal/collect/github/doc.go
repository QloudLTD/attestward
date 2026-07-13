// Package github implements the collect.Collector interface against the GitHub
// REST and GraphQL APIs. It owns authentication, rate-limit/backoff handling,
// and the worker pool used to parallelize per-repo collection; the individual
// checks (C01-C10) are added collector by collector starting with issue #9.
package github
