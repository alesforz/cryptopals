package cptext

import "testing"

func TestComputeScorePrefersEnglish(t *testing.T) {
	tests := []struct {
		name    string
		english string
		other   string
	}{
		{
			name:    "digits_vs_english",
			english: "this is a test",
			other:   "invoice 1234567890",
		},
		{
			name:    "odd_punct_vs_english",
			english: "this is fine",
			other:   "rate is 5% & rising",
		},
		{
			name:    "non_printable_vs_english",
			english: "plain text",
			other:   "plain\x00text",
		},
		{
			name:    "common_punct_vs_english",
			english: "wait, what?",
			other:   "wait; what?? 404",
		},
		{
			name:    "digits_and_punct",
			english: "meet me at 5:30 pm.",
			other:   "meet me at 5:30 pm#",
		},
		{
			name:    "mixed_english_vs_odd_char",
			english: "call me at 555-0123.",
			other:   "call me at 555~0123.",
		},
		{
			name:    "mixed_english_vs_control",
			english: "file 2 is ok.",
			other:   "file 2 is ok\x7f",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engScore := ComputeScore([]byte(tt.english))
			othScore := ComputeScore([]byte(tt.other))
			if engScore <= othScore {
				t.Errorf(
					"expected english > other: %.4f <= %.4f",
					engScore,
					othScore,
				)
			}
		})
	}
}
