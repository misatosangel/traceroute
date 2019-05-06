// +build !windows
// Copyright 2018-2019 "Misato's Angel" <misatos.arngel@gmail.com>.
// Use of this source code is governed the MIT license.
// license that can be found in the LICENSE file.

package traceroute

import (
	"errors"
	"fmt"
	"math"
	"net"
	"os/exec"
	"regexp"
	"strconv"
)

func buildTraceRouteCommand(ip, cmdPath, iface string, hops, ttl int) *exec.Cmd {
	args := make([]string, 0, 10)
	if cmdPath == "" {
		cmdPath = "traceroute"
	}
	args = append(args, "-n", "-q", "3")
	if iface != "" {
		args = append(args, "-i", iface)
	}
	if hops != 0 {
		args = append(args, "-m", fmt.Sprintf("%d", hops))
	}
	if ttl != 0 {
		// ttl in milliseconds, convert to seconds
		ttl_s := int(math.Ceil(float64(ttl) / 1000))
		args = append(args, "-w", fmt.Sprintf("%d", ttl_s))
	}
	args = append(args, ip)
	return exec.Command(cmdPath, args...)
}

func traceRouteMatchRegexp() *regexp.Regexp {
	return regexp.MustCompile(`\s+(\d+)\s+(\d\S+)\s+(\*|\d+\.\d+ ms)\s+(\*|\d+\.\d+ ms)\s+(\*|\d+\.\d+ ms)`)
}

func parseTraceRouteMatches(matches []string) (*TraceRoute, error) {
	pos, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("Could not parse position: '%s' to integer ''%s'\n", matches[0], err.Error())
	}

	ip := net.ParseIP(matches[2])
	if ip == nil {
		return nil, fmt.Errorf("Could not parse ip string: '%s' to ip\n", matches[2])
	}
	var total float64
	cnt := 0
	times := matches[3:]
	for _, val := range times {
		if val == "*" {
			continue
		}
		l := len(val) // need to trim the " ms" ender
		f, err := strconv.ParseFloat(val[0:l-3], 64)
		if err != nil {
			return nil, fmt.Errorf("Could not parse time: '%s' to float ''%s'\n", val, err.Error())
		}
		total += f
		cnt++
	}
	trace := &TraceRoute{
		Position: uint64(pos),
		IP:       ip,
	}
	if cnt == 0 {
		return trace, errors.New("No parseable times")
	}
	trace.Time = total / float64(cnt)
	return trace, nil
}
