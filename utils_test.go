package policy

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsContainsInList(t *testing.T) {
	// Test empty list
	list := []int{}
	s := 5
	assert.False(t, isContainsInList(list, s))

	// Test single-element list that contains s
	list = []int{5}
	assert.True(t, isContainsInList(list, s))

	// Test single-element list that does not contain s
	list = []int{10}
	assert.False(t, isContainsInList(list, s))

	// Test multiple-element list that contains s
	list = []int{2, 4, 5, 7}
	assert.True(t, isContainsInList(list, s))

	// Test multiple-element list that does not contain s
	list = []int{2, 4, 7, 8}
	assert.False(t, isContainsInList(list, s))
}

func TestIsEquals(t *testing.T) {
	// Test with equal integers
	a := 5
	b := 5
	assert.True(t, isEquals(a, b))

	// Test with unequal integers
	a = 5
	b = 10
	assert.False(t, isEquals(a, b))

	// Test with equal strings
	c := "hello"
	d := "hello"
	assert.True(t, isEquals(c, d))

	// Test with unequal strings
	c = "hello"
	d = "world"
	assert.False(t, isEquals(c, d))
}
