//  cryptoPAN
//
//  Preserving Both Privacy and Utility in Network Trace Anonymization
//
//  Copyright (c) 2023 Fabian Fröhlich <mail@f-froehlich.de> <https://f-froehlich.de>
//
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as
//  published by the Free Software Foundation, either version 3 of the
//  License, or (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.
//
//  You should have received a copy of the GNU Affero General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
//  For all license terms see README.md and LICENSE Files in root directory of this Project.
//
//  Checkout this project on github <https://github.com/f-froehlich/cryptoPAN>
//  and also my other projects <https://github.com/f-froehlich>

package cryptoPAN

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
)

// CryptoPAnConfig is a struct to hold the Crypto-PAn configuration.
type CryptoPAn struct {
	key          []byte
	secretPad    []byte
	first4bytes  uint32
	first4bytes2 uint64
	rijndael     cipher.Block
}

// NewCryptoPAn creates a new CryptoPAnConfig instance with the provided encryption key.
func NewCryptoPAn(key []byte) (*CryptoPAn, error) {
	if len(key) != 64 {
		return nil, errors.New("invalid key length, it should be 64 bytes")
	}

	// Split the 32-byte key into a 16-byte key for Rijndael and a 16-byte secret pad.
	rijndaelKey := key[:32]
	secretPad := key[32:64]

	block, err := aes.NewCipher(rijndaelKey)
	if err != nil {
		return nil, err
	}

	// Encrypt the 16-byte secret pad with Rijndael.
	block.Encrypt(secretPad, secretPad)

	// Get the first 4 bytes of the secret pad as a uint32 in network order.
	first4bytes := binary.BigEndian.Uint32(secretPad)

	return &CryptoPAn{
		key:         key,
		secretPad:   secretPad,
		first4bytes: first4bytes,
		rijndael:    block,
	}, nil
}

// Anonymize sanitizes the given IP address using Crypto-PAn.
func (cp *CryptoPAn) AnonymizeIPv4(ip net.IP) (net.IP, error) {
	ipBytes := ip.To4()
	if ipBytes == nil {
		return nil, errors.New("invalid IPv4 address")
	}

	// Initialize the result as a uint32 IP address.
	result := binary.BigEndian.Uint32(ipBytes)

	// Loop through each bit position and apply Crypto-PAn.
	for position := 0; position < 32; position++ {
		// Create the input block for Rijndael.
		input := make([]byte, aes.BlockSize)
		input[0] = byte(cp.first4bytes >> 24)

		// Shift and mask the input block based on the bit position.
		shiftedInput := (uint32(result) << uint(position)) | (cp.first4bytes >> uint(32-position))
		binary.BigEndian.PutUint32(input[1:], shiftedInput)

		// Encrypt the input block with Rijndael.
		cp.rijndael.Encrypt(input, input)

		// Extract the most significant bit of the first byte as the anonymized bit.
		anonymizedBit := (input[0] >> 7) & 1

		// Set the corresponding bit in the result.
		result |= uint32(anonymizedBit) << uint(31-position)
	}

	// Create the anonymized IP address.
	anonymizedIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(anonymizedIP, result)

	return anonymizedIP, nil
}

// AnonymizeIPv6 sanitizes the given IPv6 address using Crypto-PAn.
func (cp *CryptoPAn) AnonymizeIPv6(ip net.IP) (net.IP, error) {
	ipBytes := ip.To16()
	if ipBytes == nil {
		return nil, errors.New("invalid IPv6 address")
	}

	// Initialize the result as a uint128 IPv6 address.
	result := new(big.Int)
	result.SetBytes(ipBytes)

	// Convert cp.first4bytes to a big.Int
	secretPadBigInt := new(big.Int).SetUint64(uint64(cp.first4bytes))

	// Loop through each bit position and apply Crypto-PAn.
	for position := 0; position < 128; position++ {
		// Create the input block for Rijndael.
		input := make([]byte, aes.BlockSize)
		input[0] = byte(cp.first4bytes >> 24)

		// Shift and mask the input block based on the bit position.
		shiftedInput := new(big.Int).Lsh(result, uint(position)).Or(result, new(big.Int).Rsh(secretPadBigInt, uint(128-position)))
		binary.BigEndian.PutUint64(input[8:], shiftedInput.Uint64())

		// Encrypt the input block with Rijndael.
		cp.rijndael.Encrypt(input, input)

		// Extract the most significant bit of the first byte as the anonymized bit.
		anonymizedBit := (input[0] >> 7) & 1

		// Set the corresponding bit in the result.
		result.SetBit(result, 127-position, uint(anonymizedBit))
	}

	// Create the anonymized IPv6 address.
	anonymizedIP := make(net.IP, 16)
	copy(anonymizedIP, result.Bytes())

	return anonymizedIP, nil
}

func (cp *CryptoPAn) Anonymize(ip net.IP) (net.IP, error) {
	if nil == ip.To4() {
		// IPv6
		return cp.AnonymizeIPv6(ip)
	}

	// IPv4
	return cp.AnonymizeIPv4(ip)
}
