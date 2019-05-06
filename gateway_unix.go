// +build !windows
// Copyright 2018-2019 "Misato's Angel" <misatos.arngel@gmail.com>.
// Use of this source code is governed the MIT license.
// license that can be found in the LICENSE file.

package traceroute

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"regexp"
)

func FindGateway(destIP, cmdPath, iface string, localIP net.IP) (net.IP, error) {
	matcher := regexp.MustCompile(`\s*gateway: (.*)$`)
	if cmdPath == "" {
		cmdPath = "route"
	}
	cmd := exec.Command(cmdPath, "-n", "get", "-ifscope", iface, destIP)
	reader, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	err = cmd.Start()
	if err != nil {
		return nil, err
	}
	lineReader := bufio.NewScanner(reader)
	var matchErr error
	var gateway net.IP
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
		matches := matcher.FindAllStringSubmatch(lineReader.Text(), -1)
		if matches == nil {
			continue
		}
		gateway = net.ParseIP(matches[0][1])
		if gateway == nil {
			matchErr = fmt.Errorf("Could not parse IP from '%s' in line: '%s'\n", matches[0][1], lineReader.Text())
		}
	}
	err = cmd.Wait()
	if err != nil {
		return nil, err
	}
	return gateway, matchErr
}
