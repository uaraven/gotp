// SPDX-FileCopyrightText: 2021 Oleksiy Voronin <me@ovoronin.info>
// SPDX-License-Identifier: MIT

package gotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"hash"
)

type Hotp struct {
	key              []byte
	hashfunc         hash.Hash
	digits           int
	TruncationOffset int
}

func hmac_sha1(key, data []byte) []byte {
	hm := hmac.New(sha1.New, key)
	hm.Write(data)
	return hm.Sum([]byte{})
}

func NewHotp(key []byte, digits int) *Hotp {
	if len(key) > sha1.BlockSize { // if key is longer than block size
		keyHash := sha1.Sum(key)
		key = keyHash[:]
	}
	if len(key) < sha1.BlockSize { // pad the key if needed
		key = append(key, make([]byte, sha1.BlockSize-len(key))...)
	}
	return &Hotp{
		key:              key,
		digits:           digits,
		TruncationOffset: -1,
	}
}

var powers = []int{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000}

func int64toBytes(d int64) []byte {
	result := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b := byte(d & 0xff)
		result[i] = b
		d >>= 8
	}
	return result
}

func (h *Hotp) GenerateOTP(counter int64) string {
	text := int64toBytes(counter)
	hash := hmac_sha1(h.key, text)
	var offset int = int(hash[len(hash)-1] & 0xf)
	if h.TruncationOffset >= 0 && h.TruncationOffset < h.hashfunc.Size()-4 {
		offset = h.TruncationOffset
	}
	binary := (int(hash[offset]&0x7f) << 24) |
		(int(hash[offset+1]&0xff) << 16) |
		(int(hash[offset+2]&0xff) << 8) |
		(int(hash[offset+3]) & 0xff)
	otp := binary % powers[h.digits]
	return fmt.Sprintf("%0*d", h.digits, otp)
}
