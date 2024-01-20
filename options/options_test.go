package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_toMsgType(t *testing.T) {
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
			assert.Equal(t, tc.expected, toMsgType(tc.data))
		})
	}
}

func Test_toMac(t *testing.T) {
	var tests = []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "f8:b5:4d:d7:15:3f",
			data:     []byte{248, 181, 77, 215, 21, 63}, // dec -> binary split into 4 bit blocks conver to hex (248 -> 11111000 -> 1111 && 1000 -> f8
			expected: "f8:b5:4d:d7:15:3f",
		},
		{
			name:     "empty",
			data:     []byte{}, // dec -> binary split into 4 bit blocks conver to hex (248 -> 11111000 -> 1111 && 1000 -> f8
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, toMac(tc.data))
		})
	}
}
