package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_msgType(t *testing.T) {
	var tests = []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "Unspecified",
			data:     []byte{0},
			expected: "Unspecified",
		},

		{
			name:     "Discover",
			data:     []byte{1},
			expected: "Discover",
		},
		{
			name:     "Offer",
			data:     []byte{2},
			expected: "Offer",
		},
		{
			name:     "Request",
			data:     []byte{3},
			expected: "Request",
		},
		{
			name:     "Decline",
			data:     []byte{4},
			expected: "Decline",
		},
		{
			name:     "Ack",
			data:     []byte{5},
			expected: "Ack",
		},
		{
			name:     "Nak",
			data:     []byte{6},
			expected: "Nak",
		},
		{
			name:     "Release",
			data:     []byte{7},
			expected: "Release",
		},
		{
			name:     "Inform",
			data:     []byte{8},
			expected: "Inform",
		},
		{
			name:     "Unknown",
			data:     []byte{9},
			expected: "Unknown",
		},
		{
			name:     "invalid",
			data:     []byte{0, 0},
			expected: "INVALID",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, msgType(tc.data), tc.expected)
		})
	}
}
