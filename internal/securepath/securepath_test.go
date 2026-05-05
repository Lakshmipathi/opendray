package securepath_test

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/opendray/opendray/internal/securepath"
)

func TestJoin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("UNIX path semantics; Windows test would use different fixtures")
	}

	cases := []struct {
		name      string
		root      string
		parts     []string
		want      string
		wantErr   string
		wantEscape bool
	}{
		{
			name:  "single part",
			root:  "/srv/data",
			parts: []string{"foo.txt"},
			want:  "/srv/data/foo.txt",
		},
		{
			name:  "multiple parts",
			root:  "/srv/data",
			parts: []string{"sub", "foo.txt"},
			want:  "/srv/data/sub/foo.txt",
		},
		{
			name:  "trailing slash on root normalised",
			root:  "/srv/data/",
			parts: []string{"foo"},
			want:  "/srv/data/foo",
		},
		{
			name:  "empty parts returns clean root",
			root:  "/srv/data",
			parts: nil,
			want:  "/srv/data",
		},
		{
			name:  "empty string part",
			root:  "/srv/data",
			parts: []string{""},
			want:  "/srv/data",
		},
		{
			name:  "current-dir reference",
			root:  "/srv/data",
			parts: []string{".", "foo"},
			want:  "/srv/data/foo",
		},
		{
			name:  "internal dotdot stays inside root",
			root:  "/srv/data",
			parts: []string{"a", "b", "..", "c"},
			want:  "/srv/data/a/c",
		},
		{
			name:       "single dotdot escapes",
			root:       "/srv/data",
			parts:      []string{".."},
			wantEscape: true,
		},
		{
			name:       "dotdot prefix escapes",
			root:       "/srv/data",
			parts:      []string{"../etc/passwd"},
			wantEscape: true,
		},
		{
			name:       "deep dotdot escapes",
			root:       "/srv/data",
			parts:      []string{"a", "..", "..", "etc"},
			wantEscape: true,
		},
		{
			name:       "dotdot in second arg escapes",
			root:       "/srv/data",
			parts:      []string{"a/b", "../../../etc"},
			wantEscape: true,
		},
		{
			name:  "leading slash in part is mounted under root",
			root:  "/srv/data",
			parts: []string{"/etc/passwd"},
			want:  "/srv/data/etc/passwd",
		},
		{
			name:    "relative root rejected",
			root:    "data",
			parts:   []string{"foo"},
			wantErr: "must be absolute",
		},
		{
			name:    "empty root rejected",
			root:    "",
			parts:   []string{"foo"},
			wantErr: "must be absolute",
		},
		{
			name:  "root with double slashes normalised",
			root:  "/srv//data",
			parts: []string{"foo"},
			want:  "/srv/data/foo",
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got, err := securepath.Join(c.root, c.parts...)

			if c.wantEscape {
				if !errors.Is(err, securepath.ErrEscapesRoot) {
					t.Fatalf("want ErrEscapesRoot, got %v (got=%q)", err, got)
				}
				return
			}
			if c.wantErr != "" {
				if err == nil {
					t.Fatalf("want err containing %q, got nil (got=%q)", c.wantErr, got)
				}
				if !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("want err containing %q, got %v", c.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != c.want {
				t.Errorf("Join(%q, %v) = %q, want %q", c.root, c.parts, got, c.want)
			}
		})
	}
}

func TestJoin_RootIsResultWhenNoParts(t *testing.T) {
	got, err := securepath.Join("/srv/data")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "/srv/data" {
		t.Errorf("Join(root) = %q, want %q", got, "/srv/data")
	}
}

func TestJoin_ErrEscapesRootSentinel(t *testing.T) {
	_, err := securepath.Join("/srv/data", "..")
	if !errors.Is(err, securepath.ErrEscapesRoot) {
		t.Fatalf("expected errors.Is(err, ErrEscapesRoot) to be true, got %v", err)
	}
}
