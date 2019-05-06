// +build windows
// Copyright 2018-2019 "Misato's Angel" <misatos.arngel@gmail.com>.
// Use of this source code is governed the MIT license.
// license that can be found in the LICENSE file.

package traceroute

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
)

func buildTraceRouteCommand(ip, cmdPath, iface string, hops, ttl int) *exec.Cmd {
	args := make([]string, 0, 10)
	if cmdPath == "" {
		cmdPath = "tracert"
	}
	args = append(args, "-d")
	if hops != 0 {
		args = append(args, "-h", fmt.Sprintf("%d", hops))
	}
	if ttl != 0 {
		args = append(args, "-w", fmt.Sprintf("%d", ttl))
	}
	args = append(args, ip)
	return exec.Command(cmdPath, args...)
}

// windows traceroute can't do sub ms so you might get e.g.
//   1     2 ms    <1 ms    <1 ms  192.168.1.1
// and the timeout lines looks like e.g.
//  13     *        *        *     Request timed out.
func traceRouteMatchRegexp() *regexp.Regexp {
	return regexp.MustCompile(`\s+(\d+)\s+(\*|<?\d+(?:\.\d+)? ms)\s+(\*|<?\d+(?:\.\d+)? ms)\s+(\*|<?\d+(?:\.\d+)? ms)\s+(\d\S+|Request)`)
}

func parseTraceRouteMatches(matches []string) (*TraceRoute, error) {
	pos, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("Could not parse position: '%s' to integer ''%s'\n", matches[0], err.Error())
	}
	mLen := len(matches)
	var total float64
	cnt := 0
	times := matches[2 : mLen-1]
	for _, val := range times {
		if val == "*" {
			continue
		}
		if val == "<1 ms" { // windows cannot into sub-ms accuracy
			total += 0.999
			cnt++
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
	}
	if matches[mLen-1] != "Request" {
		ip := net.ParseIP(matches[mLen-1])
		if ip == nil {
			return nil, fmt.Errorf("Could not parse ip string: '%s' to ip\n", matches[mLen-1])
		}
		trace.IP = ip
	}
	if cnt == 0 {
		return trace, errors.New("No parseable times")
	}
	trace.Time = total / float64(cnt)
	return trace, nil
}
