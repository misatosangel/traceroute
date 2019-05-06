// Copyright 2018-2019 "Misato's Angel" <misatos.arngel@gmail.com>.
// Use of this source code is governed the MIT license.
// license that can be found in the LICENSE file.

package traceroute

import (
	"fmt"
	"net"
	"regexp"
	"testing"
)

type IPTest struct {
	ip     string
	result bool
}

type IPParseTest struct {
	input     string
	ip        string
	port      int
	hostname  string
	remainder string
	errMatch  *regexp.Regexp
}

func TestIPPublic(t *testing.T) {
	tests := []IPTest{
		IPTest{"192.168.0.1", false},
		IPTest{"10.0.0.1", false},
		IPTest{"192.168.10.1", false},
		IPTest{"192.169.0.1", true},
		IPTest{"172.16.10.1", false},
		IPTest{"10.145.101.1", false},
		IPTest{"81.101.101.1", true},
		IPTest{"::1", false},
		IPTest{"fe80::8e85:90ff:fe2b:818f", false},
	}

	for _, test := range tests {
		ip := net.ParseIP(test.ip)
		public := IsPublicIP(ip)
		if public && !test.result {
			t.Errorf("IP: " + test.ip + " was considered public when private\n")
		} else if !public && test.result {
			t.Errorf("IP: " + test.ip + " was considered private when public\n")
		}
	}
}

func TestParseIPPort(t *testing.T) {
	localIps, err := net.LookupIP("localhost")
	if err != nil {
		t.Errorf("Unable to lookup localhost: %s\n", err.Error())
		return
	}
	localIP := localIps[0].String()
	tests := []IPParseTest{
		IPParseTest{"81.101.101.1", "81.101.101.1",
			0, "", "", nil},
		IPParseTest{"loo loo 81.101.101.1", "81.101.101.1",
			0, "", "", nil},
		IPParseTest{"81.101.101.1and something else", "81.101.101.1",
			0, "", "and something else", nil},
		IPParseTest{"81.101.101.1:1200 and something else", "81.101.101.1",
			1200, "", " and something else", nil},
		IPParseTest{"la la 81.101.101.1:1200 and something else", "81.101.101.1",
			1200, "", " and something else", nil},
		IPParseTest{"lala81.101.101.1:1200 and something else", "81.101.101.1",
			1200, "", " and something else", nil},
		IPParseTest{"X81.101.101.1:1200YY a 101.101.101.101", "81.101.101.1",
			1200, "", "YY a 101.101.101.101", nil},
		IPParseTest{"localhost:1200YY", localIP,
			1200, "", "YY", regexp.MustCompile("non-public facing")},
		IPParseTest{"YYYlocalhost:1200YY", localIP,
			1200, "", "YY", regexp.MustCompile("non-public facing")},
	}
	for _, test := range tests {
		ip, port, hostname, remainder, err := ParseDeeplyEmbeddedIPPort(test.input, "udp", false)
		var expIP net.IP
		if test.ip == "" {
			t.Errorf("Fatal: NO IP for this test\n")
			return
		} else {
			expIP = net.ParseIP(test.ip)
			if expIP == nil {
				t.Errorf("Fatal: Cannot parse the input IP: '" + test.ip + "' for this test\n")
				continue
			}
		}
		if ip == nil {
			if expIP != nil {
				t.Errorf("In '" + test.input + "' Parsed IP: (nil) did not match expected: " + expIP.String() + "\n")
			}
		} else if expIP == nil {
			t.Errorf("In '" + test.input + "' Parsed IP: " + ip.String() + " did not match expected: (nil)\n")
		} else if !ip.Equal(expIP) {
			t.Errorf("In '" + test.input + "' Parsed IP: " + ip.String() + " did not match expected: " + expIP.String() + "\n")
		}
		if port != test.port {
			t.Errorf("In '" + test.input + "' port: " + fmt.Sprintf("%d", port) + " did not match expected: " + fmt.Sprintf("%d", test.port) + "\n")
		}
		if hostname != test.hostname {
			t.Errorf("In '" + test.input + "' hostname: '" + hostname + "' did not match expected: '" + test.hostname + "'\n")
		}
		if remainder != test.remainder {
			t.Errorf("In '" + test.input + "' remainder: '" + remainder + "' did not match expected: '" + test.remainder + "'\n")
		}
		if test.errMatch != nil {
			if err == nil {
				t.Errorf("In '" + test.input + "' no error was thrown, but expected something matching '" + test.errMatch.String() + "'\n")
			} else if !test.errMatch.MatchString(err.Error()) {
				t.Errorf("In '" + test.input + "' error thrown: '" + err.Error() + "' did not match '" + test.errMatch.String() + "'\n")
			}
		} else if err != nil {
			t.Errorf("In '" + test.input + "' error thrown: '" + err.Error() + "' was unexpected\n")
		}
	}

}
