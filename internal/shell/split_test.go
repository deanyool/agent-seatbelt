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
		{"echo 'a && b'", [][]string{{"echo", "a && b"}}},
		{`echo "a; b" c`, [][]string{{"echo", "a; b", "c"}}},
		{`e"c"h'o' hi`, [][]string{{"echo", "hi"}}},
		{`\rm x`, [][]string{{"rm", "x"}}},
		{"a\nb", [][]string{{"a"}, {"b"}}},
	}
	for _, tt := range tests {
		if got := Split(tt.line); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Split(%q) = %v", tt.line, got)
		}
	}
}
