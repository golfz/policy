package policy

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_convertEffectToBoolean(t *testing.T) {
	effect, err := convertStringToResultEffect("Allow")
	assert.NoError(t, err)
	assert.Equal(t, ALLOWED, effect)

	effect, err = convertStringToResultEffect("Deny")
	assert.NoError(t, err)
	assert.Equal(t, DENIED, effect)

	effect, err = convertStringToResultEffect("Invalid")
	assert.Error(t, err)
	assert.Equal(t, DENIED, effect)

	_, err = convertStringToResultEffect("")
	assert.Error(t, err)

	// Test case-insensitive
	_, err = convertStringToResultEffect("allow")
	assert.Error(t, err)

	// Test case-insensitive
	_, err = convertStringToResultEffect("deny")
	assert.Error(t, err)
}
