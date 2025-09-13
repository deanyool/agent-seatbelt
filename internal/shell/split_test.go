package shell

import (
	"reflect"
	"testing"
)

func TestSplit(t *testing.T) {
	tests := []struct {
		line string
		want [][]string
	}{
		{"ls", [][]string{{"ls"}}},
		{"ls -la", [][]string{{"ls", "-la"}}},
		{"a && b", [][]string{{"a"}, {"b"}}},
		{"a || b", [][]string{{"a"}, {"b"}}},
		{"a | b; c", [][]string{{"a"}, {"b"}, {"c"}}},
	}
	for _, tt := range tests {
		if got := Split(tt.line); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Split(%q) = %v", tt.line, got)
		}
	}
}
