package main

import (
	"path/filepath"
	"testing"
)

func TestScopeFromPackage(t *testing.T) {
	tests := map[string]string{
		"./...":              "",
		"./":                 "",
		"...":                "",
		"./as_metadata/...":  "as_metadata",
		"./as_metadata":      "as_metadata",
		"./as_metadata/":     "as_metadata",
		"as_metadata/...":    "as_metadata",
		"as_metadata":        "as_metadata",
		"./a/b/...":          "", // nested, not a single suite
		"./a,./b":            "", // multi-pattern, fall back
		"./a/...,./b/...":    "", // multi-pattern, fall back
		"github.com/x/y/...": "", // import path with slashes
	}
	for in, want := range tests {
		if got := scopeFromPackage(in); got != want {
			t.Errorf("scopeFromPackage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReportFilename(t *testing.T) {
	tests := map[string]string{
		"./...":             "conformance.md",
		"./as_metadata/...": "conformance-as_metadata.md",
		"./prm":             "conformance-prm.md",
		"./a,./b":           "conformance.md",
	}
	for in, want := range tests {
		if got := reportFilename(in); got != want {
			t.Errorf("reportFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveReportPath(t *testing.T) {
	tmp := t.TempDir()

	tests := []struct {
		name     string
		pkg      string
		dir      string
		file     string
		noReport bool
		want     string
	}{
		{
			name: "explicit report path wins",
			pkg:  "./...",
			file: "/tmp/explicit.md",
			want: "/tmp/explicit.md",
		},
		{
			name:     "no-report short-circuits everything",
			pkg:      "./as_metadata/...",
			file:     "/tmp/explicit.md",
			noReport: true,
			want:     "",
		},
		{
			name: "report-dir + full run",
			pkg:  "./...",
			dir:  tmp,
			want: filepath.Join(tmp, "conformance.md"),
		},
		{
			name: "report-dir + scoped run",
			pkg:  "./as_metadata/...",
			dir:  tmp,
			want: filepath.Join(tmp, "conformance-as_metadata.md"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveReportPath(tt.pkg, tt.dir, tt.file, tt.noReport)
			if got != tt.want {
				t.Errorf("resolveReportPath(pkg=%q, dir=%q, file=%q, noReport=%v) = %q, want %q",
					tt.pkg, tt.dir, tt.file, tt.noReport, got, tt.want)
			}
		})
	}
}
