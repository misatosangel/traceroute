// Copyright 2018-2019 "Misato's Angel" <misatos.arngel@gmail.com>.
// Use of this source code is governed the MIT license.
// license that can be found in the LICENSE file.

package traceroute

import (
	"errors"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var gNumberMatchRxp = regexp.MustCompile("^\\d+")
var gTrailingText = regexp.MustCompile("(\\d|\\])\\D+$")

// Takes a string that might be an IP address or hostname and maybe a port as well
// Returns the IP it resolves to and the port as an integer if there was one.
// Additionally if the host part was originally a host (not raw IP) it is returned as well
func ParseIPPort(what string, netType string, allowInternal bool) (net.IP, int, string, error) {
	ip, port, hostname, remainder, err := ParseEmbeddedIPPort(what, netType, allowInternal)
	if err != nil {
		return ip, port, hostname, err
	}
	if remainder != "" {
		return ip, port, hostname, errors.New("Unexpected extra text: '" + remainder + "' after IP-port.\n")
	}
	return ip, port, hostname, nil
}

func ParseDeeplyEmbeddedIPPort(what string, netType string, allowInternal bool) (net.IP, int, string, string, error) {
	for remainder := what; remainder != ""; {
		ip, port, hostname, remaining, err := ParseEmbeddedIPPort(remainder, "udp", false)
		if err == nil {
			if ip == nil && remaining != "" {
				remainder = remaining
				continue
			}
			return ip, port, hostname, remaining, err
		}
		if !allowInternal && strings.Contains(err.Error(), "non-public facing") {
			return ip, port, hostname, remaining, err
		}
		if remaining == "" {
			if remainder == "" {
				break
			}
			remainder = remainder[1:]
		} else {
			remainder = remaining
		}
	}
	return nil, 0, "", "", nil
}

func ParseEmbeddedIPPort(what string, netType string, allowInternal bool) (net.IP, int, string, string, error) {
	if len(what) == 0 {
		return nil, 0, "", "", errors.New("No ip string given to parse")
	}
	ip := net.ParseIP(what)
	if ip != nil {
		if !allowInternal && !IsPublicIP(ip) {
			return ip, 0, "", "", errors.New("IP: " + ip.String() + " is an internal (non-public facing) IP\n")
		}
		return ip, 0, "", "", nil
	}
	var p int
	host, port, hp_err := net.SplitHostPort(what)
	remainder := what[1:]
	if hp_err != nil {
		trailText := gTrailingText.FindString(what)
		if trailText != "" {
			trailCnt := len(trailText) - 1
			trimmed := what[0 : len(what)-trailCnt]
			remainder = what[len(what)-trailCnt:]
			ip = net.ParseIP(trimmed)
			if ip != nil {
				if !allowInternal && !IsPublicIP(ip) {
					return ip, 0, "", remainder, errors.New("IP: " + ip.String() + " is an internal (non-public facing) IP\n")
				}
				return ip, 0, "", remainder, nil
			}
			var err2 error
			host, port, err2 = net.SplitHostPort(trimmed)
			if err2 == nil {
				hp_err = nil
				what = trimmed
			}
		} else {
			remainder = ""
		}
		if hp_err != nil {
			return nil, 0, "", remainder, errors.New("Expected '" + what + "' to either:\n" +
				" - be an IP (v4 or v6), but it looked like neither\n" +
				" - be an IP:Port, but that did not parse either: " + hp_err.Error())
		}
	}

	portStr := gNumberMatchRxp.FindString(port)
	if portStr != "" {
		portLen := len(portStr)
		if portLen < len(port) {
			remainder = port[portLen:]
		} else {
			remainder = ""
		}
		p_u64, port_err := strconv.ParseUint(portStr, 10, 16)
		if port_err != nil {
			p2, port2_err := net.LookupPort(netType, port)
			if port2_err != nil || p2 == 0 {
				return nil, 0, "", remainder, errors.New("Port part of '" + what + "': is not numeric nor a known " + netType + " port name")
			}
			p = p2
		} else if p_u64 == 0 || p_u64 > 65535 {
			return nil, 0, "", remainder, errors.New("Port part of '" + what + "': is not between 1 and 65535")
		} else {
			p = int(p_u64)
		}
	} else {
		p2, port2_err := net.LookupPort(netType, port)
		if port2_err != nil || p2 == 0 {
			return nil, 0, "", port, errors.New("Port part of '" + what + "': is not numeric nor a known " + netType + " port name")
		}
		remainder = ""
		p = p2
	}
	ip = net.ParseIP(host)
	if ip != nil {
		if !allowInternal && !IsPublicIP(ip) {
			return ip, p, "", remainder, errors.New("IP: " + ip.String() + " is an internal (non-public facing) IP\n")
		}
		return ip, p, "", remainder, nil
	}
	// try as a host name
	ips, lookup_err := net.LookupIP(host)
	if lookup_err != nil {
		return nil, p, "", what[1:], errors.New("IP part of '" + what + "': is not a known host or IP address: " + lookup_err.Error())
	}
	filterIPs := ips
	if !allowInternal {
		filterIPs = make([]net.IP, 0, len(ips))
		for _, ip := range ips {
			if IsPublicIP(ip) {
				filterIPs = append(filterIPs, ip)
			}
		}
		if len(filterIPs) == 0 {
			var err error
			if len(ips) != 1 {
				err = errors.New("'" + host + "' resolved to internal (non-public facing) IPs\n")
			} else {
				err = errors.New("IP: " + ips[0].String() + " got from resolving '" + host + "' is an internal (non-public facing) IP\n")
			}
			return ips[0], p, "", remainder, err
		}
		ips = filterIPs
	}

	if len(ips) == 1 {
		ip = ips[0]
		if !allowInternal && !IsPublicIP(ip) {
			return ip, p, "", remainder, errors.New("IP: " + ip.String() + " got from resolving '" + host + "' is an internal (non-public facing) IP\n")
		}
		return ip, p, host, remainder, nil
	}
	s := "IP part of '" + what + "': resolves to multiple IP addresses:\n"
	for _, ip := range ips {
		s += " - " + ip.String() + "\n"
	}
	return nil, p, host, remainder, errors.New(s)
}

// IP v4 private addresses:
// Class        Starting IPAddress    Ending IP Address    # of Hosts
// A            10.0.0.0              10.255.255.255       16,777,216
// B            172.16.0.0            172.31.255.255       1,048,576
// C            192.168.0.0           192.168.255.255      65,536
// Link-local-u 169.254.0.0           169.254.255.255      65,536
// Link-local-m 224.0.0.0             224.0.0.255          256
// Local        127.0.0.0             127.255.255.255      16777216
//
// and v6:
//
func IsPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch true {
		case ip4[0] == 10:
			return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		default:
			return true
		}
	}
	// we are v6
	_, ipv6Net, err := net.ParseCIDR("fd00::/8")
	if err != nil {
		log.Fatalf("Could not parse internal CIDR: %s\n", err)
	}
	if ipv6Net.Contains(ip) {
		return false
	}
	return true
}

// attempts to find all local ips on this host
func FindLocalIPs() ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var lastError error
	ips := make([]net.IP, 0, len(ifaces))
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		// handle err
		if err != nil {
			lastError = err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ips = append(ips, ip)
		}
	}
	return ips, lastError
}
