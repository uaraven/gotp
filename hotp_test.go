// SPDX-FileCopyrightText: 2021 Oleksiy Voronin <me@ovoronin.info>
// SPDX-License-Identifier: MIT

package gotp

import "testing"

func TestHOTP(t *testing.T) {
	key := []byte("12345678901234567890")
	otp := NewHotp(key, 6)
	expected := []string{
		"755224",
		"287082",
		"359152",
		"969429",
		"338314",
		"254676",
		"287922",
		"162583",
		"399871",
		"520489",
	}
	for i := range expected {
		actual := otp.GenerateOTP(int64(i))
		if actual != expected[i] {
			t.Errorf("Counter: %d, Expected '%s', got '%s'", i, expected[i], actual)
		}
	}
}
