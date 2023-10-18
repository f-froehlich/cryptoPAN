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
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

func initCP(t *testing.T) *CryptoPAn {
	key := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	var cp, err = NewCryptoPAn(key)
	require.Nil(t, err, "There should be no errors", err)

	return cp
}

func TestCryptoPAnIp4(t *testing.T) {

	cp := initCP(t)
	originalIP := net.ParseIP("3.168.10.154")

	anonymizedIP, err := cp.Anonymize(originalIP)
	require.Nil(t, err, "There should be no errors")
	require.Equal(t, "203.174.191.191", anonymizedIP.String(), "Ip not anonymized")

	anonymizedIP2, err2 := cp.Anonymize(originalIP)
	require.Nil(t, err2, "There should be no errors")
	require.Equal(t, anonymizedIP.String(), anonymizedIP2.String(), "Ip should be the same if anonymized multiple times")

}

func TestCryptoPAnIp6(t *testing.T) {

	cp := initCP(t)
	originalIP := net.ParseIP("2001:db8::5555:6666:7777:8888")

	anonymizedIP, err := cp.Anonymize(originalIP)
	require.Nil(t, err, "There should be no errors")
	require.Equal(t, "88f9:9024:dfe1:bd00::", anonymizedIP.String(), "Ip not anonymized")

	anonymizedIP2, err2 := cp.Anonymize(originalIP)
	require.Nil(t, err2, "There should be no errors")
	require.Equal(t, anonymizedIP.String(), anonymizedIP2.String(), "Ip should be the same if anonymized multiple times")

}
