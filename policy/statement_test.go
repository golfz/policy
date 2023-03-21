package policy

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_convertEffectStringToResultEffect(t *testing.T) {
	effect, err := convertEffectStringToResultEffect("Allow")
	assert.NoError(t, err)
	assert.Equal(t, ALLOWED, effect)

	effect, err = convertEffectStringToResultEffect("Deny")
	assert.NoError(t, err)
	assert.Equal(t, DENIED, effect)

	effect, err = convertEffectStringToResultEffect("Invalid")
	assert.Error(t, err)
	assert.Equal(t, DENIED, effect)

	_, err = convertEffectStringToResultEffect("")
	assert.Error(t, err)

	// Test case-insensitive
	_, err = convertEffectStringToResultEffect("allow")
	assert.Error(t, err)

	// Test case-insensitive
	_, err = convertEffectStringToResultEffect("deny")
	assert.Error(t, err)
}
