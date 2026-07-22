package azuredevops

import (
	"net/http"
	"testing"
)

func TestIsAdvSecGated(t *testing.T) {
	cases := []struct {
		status int
		want   bool
	}{
		{http.StatusOK, false},
		{http.StatusForbidden, true},
		{http.StatusNotFound, true},
		{http.StatusTooManyRequests, false},
		{http.StatusInternalServerError, false},
	}
	for _, tc := range cases {
		if got := IsAdvSecGated(tc.status); got != tc.want {
			t.Errorf("IsAdvSecGated(%d) = %v, want %v", tc.status, got, tc.want)
		}
	}
}

func TestIsAuditGated(t *testing.T) {
	cases := []struct {
		status int
		want   bool
	}{
		{http.StatusOK, false},
		{http.StatusForbidden, true},
		{http.StatusNotFound, true},
		{http.StatusTooManyRequests, false},
		{http.StatusInternalServerError, false},
	}
	for _, tc := range cases {
		if got := IsAuditGated(tc.status); got != tc.want {
			t.Errorf("IsAuditGated(%d) = %v, want %v", tc.status, got, tc.want)
		}
	}
}
