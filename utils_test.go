package policy

import (
	"testing"
)

func TestIsContainsInList(t *testing.T) {
	s := 5
	testCases := []struct {
		desc     string
		list     []int
		element  int
		expected bool
	}{
		{"empty list", []int{}, s, false},
		{"single-element list that contains s", []int{5}, s, true},
		{"single-element list that does not contain s", []int{10}, s, false},
		{"multiple-element list that contains s", []int{2, 4, 5, 7}, s, true},
		{"multiple-element list that does not contain s", []int{2, 4, 7, 8}, s, false},
	}

	for _, tt := range testCases {
		t.Run(tt.desc, func(t *testing.T) {
			if isContainsInList(tt.list, tt.element) != tt.expected {
				t.Errorf("Expected %v, but got %v", tt.expected, isContainsInList(tt.list, tt.element))
			}
		})
	}
}

func TestIsEquals(t *testing.T) {
	tests := []struct {
		name     string
		a        interface{}
		b        interface{}
		expected bool
	}{
		{"equal integers", 5, 5, true},
		{"unequal integers", 5, 10, false},
		{"equal strings", "hello", "hello", true},
		{"unequal strings", "hello", "world", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isEquals(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("isEquals(%v, %v) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}
