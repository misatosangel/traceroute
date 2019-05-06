// Copyright 2018-2019 "Misato's Angel" <misatos.arngel@gmail.com>.
// Use of this source code is governed the MIT license.
// license that can be found in the LICENSE file.

package traceroute

import (
	"bufio"
	"fmt"
	"net"
)

type TraceRoute struct {
	Position uint64
	IP       net.IP
	Time     float64
}

func Trace(ip, cmdPath, iface string, hops, ttl int) ([]TraceRoute, error) {
	cmd := buildTraceRouteCommand(ip, cmdPath, iface, hops, ttl)
	reader, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	err = cmd.Start()
	if err != nil {
		return nil, err
	}
	lineReader := bufio.NewScanner(reader)
	matcher := traceRouteMatchRegexp()
	max := hops
	if max == 0 {
		max = 10
	}
	out := make([]TraceRoute, 0, max)
	for lineReader.Scan() {
		// traceroute lines look like:
		// position(int) IP (float) ms (float) ms (float) ms
		// Any float might be '*' if timeout occurred.
		// e.g.
		// 1  82.27.181.244  1.104 ms  0.710 ms  0.710 ms
		err = lineReader.Err()
		if err != nil {
			_ = cmd.Wait()
			return nil, err
		}
		matches := matcher.FindAllStringSubmatch(lineReader.Text(), -1)
		if matches == nil {
			continue
		}
		route, err := parseTraceRouteMatches(matches[0])
		if route == nil && err != nil {
			continue
		}
		out = append(out, *route)
	}
	err = cmd.Wait()
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (self *TraceRoute) String() string {
	if self.IP == nil {
		return fmt.Sprintf("%d. Timed out", self.Position)
	}
	return fmt.Sprintf("%d. [%f] %s", self.Position, self.Time, self.IP.String())
}
