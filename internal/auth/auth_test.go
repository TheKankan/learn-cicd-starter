package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expected    string
		expectedErr error
	}{
		{
			name:        "Header absent",
			headers:     http.Header{},
			expected:    "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Header valide",
			headers:     http.Header{"Authorization": []string{"ApiKey ma-super-cle"}},
			expected:    "ma-super-cle",
			expectedErr: nil,
		},
		{
			name:        "Mauvais préfixe (Bearer au lieu de ApiKey)",
			headers:     http.Header{"Authorization": []string{"Bearer un-token"}},
			expected:    "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "Header malformé (pas d'espace)",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expected:    "",
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			if got != tt.expected {
				t.Errorf("valeur attendue %q, obtenu %q", tt.expected, got)
			}

			if tt.expectedErr != nil {
				if err == nil {
					t.Errorf("erreur attendue %q, mais pas d'erreur retournée", tt.expectedErr)
				} else if err.Error() != tt.expectedErr.Error() {
					t.Errorf("erreur attendue %q, obtenu %q", tt.expectedErr, err)
				}
			} else if err != nil {
				t.Errorf("pas d'erreur attendue, mais obtenu %q", err)
			}
		})
	}
}
