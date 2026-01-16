// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import "testing"

func TestSanitizeForLog(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "clean string unchanged",
			input:    "/peer",
			expected: "/peer",
		},
		{
			name:     "newline escaped",
			input:    "/peer\nfake log entry",
			expected: "/peer\\nfake log entry",
		},
		{
			name:     "carriage return escaped",
			input:    "/peer\rfake log entry",
			expected: "/peer\\rfake log entry",
		},
		{
			name:     "CRLF escaped",
			input:    "/peer\r\nfake log entry",
			expected: "/peer\\r\\nfake log entry",
		},
		{
			name:     "multiple newlines escaped",
			input:    "line1\nline2\nline3",
			expected: "line1\\nline2\\nline3",
		},
		{
			name:     "null byte removed",
			input:    "/peer\x00injected",
			expected: "/peerinjected",
		},
		{
			name:     "bell character removed",
			input:    "/peer\x07alert",
			expected: "/peeralert",
		},
		{
			name:     "tab preserved",
			input:    "/peer\tvalue",
			expected: "/peer\tvalue",
		},
		{
			name:     "mixed control characters",
			input:    "/peer\n\x00\x07\r\x1b[31mred",
			expected: "/peer\\n\\r[31mred",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "URL encoded newline in path",
			input:    "/peer%0afake",
			expected: "/peer%0afake",
		},
		{
			name:     "unicode preserved",
			input:    "/peer/日本語",
			expected: "/peer/日本語",
		},
		{
			name:     "log injection attempt",
			input:    "/peer\n2026/01/15 12:00:00 FAKE: admin logged in",
			expected: "/peer\\n2026/01/15 12:00:00 FAKE: admin logged in",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeForLog(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeForLog(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "short string unchanged",
			input:    "hello",
			maxLen:   10,
			expected: "hello",
		},
		{
			name:     "exact length unchanged",
			input:    "hello",
			maxLen:   5,
			expected: "hello",
		},
		{
			name:     "long string truncated",
			input:    "hello world",
			maxLen:   5,
			expected: "hello...",
		},
		{
			name:     "empty string",
			input:    "",
			maxLen:   5,
			expected: "",
		},
		{
			name:     "zero max length",
			input:    "hello",
			maxLen:   0,
			expected: "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, result, tt.expected)
			}
		})
	}
}
