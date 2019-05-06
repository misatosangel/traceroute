// +build windows
// Copyright 2018-2019 "Misato's Angel" <misatos.arngel@gmail.com>.
// Use of this source code is governed the MIT license.
// license that can be found in the LICENSE file.

package traceroute

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func FindGateway(destIP, cmdPath, iface string, localIP net.IP) (net.IP, error) {
	if cmdPath == "" {
		cmdPath = "route"
	}
	cmd := exec.Command(cmdPath, "print")
	reader, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	err = cmd.Start()
	if err != nil {
		return nil, err
	}
	lineReader := bufio.NewScanner(reader)

	var gateway net.IP
	position := 0
	breaks := 0
	destIPasIP := net.ParseIP(destIP)
	if destIPasIP == nil {
		return nil, fmt.Errorf("Bad IP stirng passed: '%s'\n", destIP)
	}
	isIPv6 := true
	if destIPasIP.To4() != nil {
		isIPv6 = false
	}

	for lineReader.Scan() {
		// looking for a line like:
		// gateway: 192.168.1.1
		err = lineReader.Err()
		if err != nil {
			_ = cmd.Wait()
			return nil, err
		}
		if gateway != nil {
			continue
		}
		line := lineReader.Text()
		switch position {
		case 0: // looking for "Active Routes:"
			if strings.HasPrefix(line, "==================") {
				breaks++
				if breaks == 3 {
					position++
				}
			}
		case 1, 2: // in the IPv4 address table header
			position++ // Active routes:  and table headers
		case 3: // in the IPv4 table
			if strings.HasPrefix(line, "==================") {
				if isIPv6 {
					position = 4 // search for ipv6 area
				} else {
					position = 9 // skip everything else
				}
				continue
			}
			if isIPv6 {
				continue // no point looking here
			}
			// example line:
			// 0.0.0.0          0.0.0.0      10.211.55.1     10.211.55.3       10
			// these are [0]destination, [1]net-mask, [2]gateway, [3]interface and [4]weight metric
			line = strings.TrimSpace(line)
			ipBlocks := strings.Fields(line)
			if len(ipBlocks) < 4 {
				// might be a default gateway comment
				continue
			}
			// we want to find one that matches our IP (interface) but whose gateway doesn't.
			ifaceIP := net.ParseIP(ipBlocks[3])
			if ifaceIP == nil || !ifaceIP.Equal(localIP) {
				continue
			}
			gwayIP := net.ParseIP(ipBlocks[2])
			if gwayIP == nil || gwayIP.Equal(localIP) {
				continue
			}
			gateway = gwayIP
		case 4: // finished v4, searching for v6
			if strings.Contains(line, "IPv6") {
				position = 5
			}
		case 5, 6, 7: // found v6 header, skip next three lines
			position++
		case 8:
			if strings.HasPrefix(line, "==================") {
				position = 9 // we're done
			}
			line = strings.TrimSpace(line)
			ipBlocks := strings.Fields(line)
			// example line:
			// 15   9005 ::/0 2620:9b::1900:1
			// these are [0]IF#, [1]weight metric, [2]Network Dest, [3]Gateway
			_, anet, err := net.ParseCIDR(ipBlocks[2])
			if err != nil || !anet.Contains(destIPasIP) {
				continue
			}
			gateway = net.ParseIP(ipBlocks[3])
		}
		continue
	}
	err = cmd.Wait()
	if err != nil {
		return nil, err
	}
	if gateway == nil {
		return nil, fmt.Errorf("No gateway info found")
	}
	return gateway, nil
}
