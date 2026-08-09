// Package integrity seals an evidence pack: SHA-256 hashing (always on) and
// optional cosign sign-blob signing (shelled out to, not vendored — see the
// mini-ADR tracked in issue #27) so a pack handed to a third party is
// tamper-evident.
package integrity
