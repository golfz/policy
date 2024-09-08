package policy

import (
	"reflect"
	"testing"
)

func TestGetUserProperty(t *testing.T) {
	userDataStr := `
		{	
			"employee": {
				"company": {
					"title": "Hello inc.",
					"established": 1983,
					"geolocation": {
						"latitude": 37.7749,
						"longitude": -122.4194
					},
					"active": true
				}
			}	
		}`

	tt := []struct {
		name     string
		userData string
		key      string
		expect   string
	}{
		{
			name:     "get correct nested key, return value",
			userData: userDataStr,
			key:      "user:::employee:company:title",
			expect:   "Hello inc.",
		},
		{
			name:     "none existent key, return empty string",
			userData: userDataStr,
			key:      "user:::employee:company:address",
			expect:   "",
		},
		{
			name:     "empty key, return empty string",
			userData: userDataStr,
			key:      "",
			expect:   "",
		},
		{
			name:     "empty userData, return empty string",
			userData: "",
			key:      "user:::employee:company:address",
			expect:   "",
		},
		{
			name:     "integer value, return as string",
			userData: userDataStr,
			key:      "employee:company:established",
			expect:   "1983",
		},
		{
			name:     "float value, return as string",
			userData: userDataStr,
			key:      "employee:company:geolocation:latitude",
			expect:   "37.7749",
		},
		{
			name:     "boolean value, return as string",
			userData: userDataStr,
			key:      "employee:company:active",
			expect:   "true",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ug := NewDefaultUserPropertyGetter(tc.userData)
			got := ug.GetUserProperty(tc.key)
			if !reflect.DeepEqual(got, tc.expect) {
				t.Errorf("Got '%v'; expect '%v'", got, tc.expect)
			}
		})
	}
}
