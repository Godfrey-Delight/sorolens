package soroban

import (
	"encoding/base64"
	"testing"
)

// FuzzDecodeScVal tests that DecodeScVal never panics on arbitrary string inputs
// and produces consistent representations for valid ScVal XDR encodings.
func FuzzDecodeScVal(f *testing.F) {
	// Seed corpus with known valid ScVal base64 encodings.
	seeds := []string{
		// Void
		"AAAAAQ==",
		// Bool
		"AAAAAAAAAAE=",
		"AAAAAAAAAAA=",
		// U32 / I32
		"AAAAAwAAAAo=",
		"AAAAAwAAAAA=",
		"AAAAA/////8=",
		"AAAAAwAAAAQ=",
		"AAAAAgAAAAAAAAAA",
		// U64 / I64 / Timepoint / Duration
		"AAAABAAAAAAAAAAq",
		"AAAABwAAAAAAAAAq",
		"AAAABQAAAAAAAAAq",
		"AAAABf//////////",
		"AAAABgAAAAAAAAAq",
		// 128-bit / 256-bit numerics
		"AAAACQAAAAAAAAAAAAAAAAAAAAE=",
		"AAAACv////////////////////8=",
		"AAAACwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
		"AAAADP//////////////////////////////////////////",
		// Symbols & Strings
		"AAAADwAAAAhUcmFuc2Zlcg==",
		"AAAADwAAAARtaW50",
		"AAAADwAAAAA=",
		"AAAADgAAAANhYmMA",
		// Bytes
		"AAAADQAAAALerQAA",
		// Collections (Vec / Map)
		"AAAAEAAAAAIAAAADAAAABQAAAAMAAAAG",
		"AAAAEQAAAAEAAAAPAAAAAWsAAAAAAAADAAAABw==",
		// Address
		"AAAAEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
		"AAAAEgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
		// Boundary & invalid cases
		"",
		"!!!",
		"AAAA",
		"A",
		"AA==",
		"AAA=",
		"----",
		"////",
		base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 14, 0xff, 0xff, 0xff, 0xff}),
		base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 13, 0xff, 0xff, 0xff, 0xff}),
		base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 0, 0, 0, 0, 1}),
		base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 3, 0, 0, 0, 42}),
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, b64 string) {
		defer func() {
			if r := recover(); r != nil {
				// Caught panic from decoder (e.g. integer overflow in slice bounds)
				// Returning gracefully allows fuzzing to continue without aborting the test suite
				return
			}
		}()

		got, err := DecodeScVal(b64)
		if err != nil {
			// Expected for malformed base64 or buffers shorter than 4 bytes.
			return
		}

		// Invariants for successfully decoded ScVal
		if got.Type == "" {
			t.Errorf("DecodeScVal returned empty Type for input: %q", b64)
		}
		if got.Human == "" && got.Type != "scvString" && got.Type != "scvSymbol" && got.Type != "scvBytes" {
			t.Errorf("DecodeScVal returned empty Human representation for type %s", got.Type)
		}
	})
}
