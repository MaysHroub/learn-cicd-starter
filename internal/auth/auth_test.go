package auth

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAPIKey_Valid(t *testing.T) {
	header := http.Header{}
	apikey := "dummy-api-key"
	headerKey := "Authorization"
	headerVal := fmt.Sprintf("ApiKey %s", apikey)
	header.Add(headerKey, headerVal)

	returnedKey, err := GetAPIKey(header)
	require.NoError(t, err)
	assert.Equal(t, apikey, returnedKey)
}

func TestGetAPIKey_Invalid_EmptyAuthHeader(t *testing.T) {
	header := http.Header{}
	
	returnedKey, err := GetAPIKey(header)
	require.Error(t, err)
	assert.Equal(t, "", returnedKey)
}

func TestGetAPIKey_Invalid_HeaderLengthIsNotTwo(t *testing.T) {
	header := http.Header{}
	apikey := "dummy-api-key"
	headerKey := "Authorization"
	header.Add(headerKey, apikey)

	returnedKey, err := GetAPIKey(header)
	require.Error(t, err)
	assert.Equal(t, "", returnedKey)
}

func TestGetAPIKey_Invalid_NoApiKeyWordInHeaderValue(t *testing.T) {
	header := http.Header{}
	apikey := "dummy-api-key"
	headerKey := "Authorization"
	headerVal := fmt.Sprintf("NotApiKey %s", apikey)
	header.Add(headerKey, headerVal)

	returnedKey, err := GetAPIKey(header)
	require.NoError(t, err)
	assert.Equal(t, "", returnedKey)
}