// SPDX-FileCopyrightText: 2021 Oleksiy Voronin <me@ovoronin.info>
// SPDX-License-Identifier: MIT

package gotp

import "crypto/sha1"

// Otp defines common functions for the one-time passwords
type Otp interface {
	GenerateOTP(counter int64) string
	Verify(otp string, counter int64) bool
}

func adjustForSha1(key []byte) []byte {
	if len(key) > sha1.BlockSize { // if key is longer than block size
		keyHash := sha1.Sum(key)
		key = keyHash[:]
	}
	if len(key) < sha1.BlockSize { // pad the key if needed
		key = append(key, make([]byte, sha1.BlockSize-len(key))...)
	}
	return key
}
