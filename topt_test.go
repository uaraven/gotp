// SPDX-FileCopyrightText: 2021 Oleksiy Voronin <me@ovoronin.info>
// SPDX-License-Identifier: MIT
package gotp

import (
	"testing"
	"time"
)

func TestTOTPGenerate(t *testing.T) {
	key := []byte("12345678901234567890")
	otp := NewToptDigits(key, 8)

	expected := otp.GenerateOTP(59)
	if expected != "94287082" {
		t.Errorf("Expected '94287082', but got %s for time=59, digits=10, T0=0", expected)
	}

	expected = otp.GenerateOTP(1111111109)
	if expected != "07081804" {
		t.Errorf("Expected '07081804', but got %s for time=1111111109, digits=10, T0=0", expected)
	}

	expected = otp.GenerateOTP(20000000000)
	if expected != "65353130" {
		t.Errorf("Expected '65353130', but got %s for time=20000000000, digits=10, T0=0", expected)
	}
}

func TestHOTPGenerateOffset(t *testing.T) {
	key := []byte("12345678901234567890")
	otp := NewTopt(key, 8, 30, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
	code := otp.At(time.Date(2000, 1, 1, 0, 0, 59, 0, time.UTC))

	if code != "94287082" {
		t.Errorf("Expected '94287082', but got %s for time=59, digits=10, T0=0", code)
	}
}

func TestTOTPVerifyDefault(t *testing.T) {
	key := []byte("12345678901234567890")
	otp := NewToptDigits(key, 8)

	if !otp.Verify("94287082", 59) {
		t.Errorf("Failed validation of OTP '94287082' at 59 seconds")
	}

	if otp.Verify("94287082", 69) {
		t.Errorf("Incorrectly validated OTP '94287082' at 69 seconds")
	}
}

func TestTOTPVerifyWithWindow(t *testing.T) {
	key := []byte("12345678901234567890")
	otp := NewToptDigits(key, 8)

	if !otp.VerifyWithinWindow("94287082", 69, 1) {
		t.Errorf("Failed validation of OTP '94287082' at 69 seconds with 1 interval window")
	}

	if !otp.VerifyWithinWindow("94287082", 31, 1) {
		t.Errorf("Failed validation of OTP '94287082' at 31 seconds with 1 interval window")
	}
}
