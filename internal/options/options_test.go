package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_decodeMsgType(t *testing.T) {
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
			assert.Equal(t, tc.expected, decodeMsgType(tc.data))
		})
	}
}

func Test_decodeMac(t *testing.T) {
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
			assert.Equal(t, tc.expected, decodeMac(tc.data))
		})
	}
}

func Test_decodeIP(t *testing.T) {
	var tests = []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "192.168.5.4",
			data:     []byte{192, 168, 5, 4},
			expected: "192.168.5.4",
		},
		{
			name:     "less than 4 octets",
			data:     []byte{},
			expected: "INVALID",
		},
		{
			name:     "more than 4 octets",
			data:     []byte{192, 168, 5, 4, 3},
			expected: "INVALID",
		},
		{
			name:     "localhost",
			data:     []byte{127, 0, 0, 1},
			expected: "127.0.0.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, decodeIP(tc.data))
		})
	}
}

func Test_decodeUint32(t *testing.T) {
	var tests = []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "86400",
			data:     []byte{0, 1, 81, 128},
			expected: "86400", // bit shifting fun (1 * 256 * 256) + (81 * 256) + (128)
		},
		{
			name:     "less than 4 bytes",
			data:     []byte{},
			expected: "INVALID",
		},
		{
			name:     "more than 4 bytes",
			data:     []byte{1, 1, 1, 1, 1},
			expected: "INVALID",
		},
		{
			name:     "1",
			data:     []byte{0, 0, 0, 1},
			expected: "1",
		},
		{
			name:     "256",
			data:     []byte{0, 0, 1, 0},
			expected: "256",
		},
		{
			name:     "65536",
			data:     []byte{0, 1, 0, 0},
			expected: "65536",
		},
		{
			name:     "16777216",
			data:     []byte{1, 0, 0, 0},
			expected: "16777216",
		},
		{
			name:     "4294967295",
			data:     []byte{255, 255, 255, 255},
			expected: "4294967295", // (255 * 256 * 256 * 256) + (255 * 256 * 256) + (255 * 256) + 255
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, decodeUint32(tc.data))
		})
	}
}

func Test_decodeUint16(t *testing.T) {
	var tests = []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "1500",
			data:     []byte{5, 220},
			expected: "1500", // more easier bit shifting (5 * 256) + 220
		},
		{
			name:     "less than 2 bytes",
			data:     []byte{},
			expected: "INVALID",
		},
		{
			name:     "more than 2 bytes",
			data:     []byte{1, 1, 1, 1, 1},
			expected: "INVALID",
		},
		{
			name:     "1",
			data:     []byte{0, 1},
			expected: "1",
		},
		{
			name:     "256",
			data:     []byte{1, 0},
			expected: "256",
		},
		{
			name:     "65535",
			data:     []byte{255, 255},
			expected: "65535",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, decodeUint16(tc.data))
		})
	}
}

func Test_decodeVendorOptions(t *testing.T) {
	var tests = []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "gordcurrie.com",
			data:     []byte{241, 14, 103, 111, 114, 100, 99, 117, 114, 114, 105, 101, 46, 99, 111, 109},
			expected: "code: 241 len: 14 data: gordcurrie.com",
		},
		{
			name: "two vendor options",
			data: []byte{241, 14, 103, 111, 114, 100, 99, 117, 114, 114, 105, 101, 46, 99, 111, 109,
				242, 13, 103, 111, 114, 100, 99, 117, 114, 114, 105, 101, 46, 99, 111},
			expected: "code: 241 len: 14 data: gordcurrie.com\ncode: 242 len: 13 data: gordcurrie.co",
		},
		{
			name:     "non-encapsulated",
			data:     []byte{143, 150, 142, 160, 55, 164, 157, 157, 154, 163},
			expected: "malformed value: \x8f\x96\x8e\xa07\xa4\x9d\x9d\x9a\xa3",
		},
		{
			name:     "empty",
			data:     []byte{},
			expected: "INVALID",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, decodeVendorOptions(tc.data))
		})
	}
}

func Test_decodeOptionParams(t *testing.T) {
	var tests = []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "single",
			data:     []byte{43},
			expected: "VendorOption (43)",
		},
		{
			name:     "multiple",
			data:     []byte{43, 44},
			expected: "VendorOption (43),\nNetBIOSOverTCPNS (44)",
		},
		{
			name:     "empty",
			data:     []byte{},
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, decodeOptionParams(tc.data))
		})
	}
}
