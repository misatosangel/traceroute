// Copyright 2018-2019 "Misato's Angel" <misatos.arngel@gmail.com>.
// Use of this source code is governed the MIT license.
// license that can be found in the LICENSE file.

package traceroute

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	WANT_PUBLIC_V4 = 1 << iota
	WANT_PUBLIC_V6
	WANT_PRIVATE_V4
	WANT_PRIVATE_V6
	WANT_LOOPBACK_V4
	WANT_LOOPBACK_V6
	WANT_LIVE_IP
)

const (
	IPFindSite = "http://myexternalip.com/raw"
)

type IPAddrMap struct {
	Local      net.Addr
	LocalIP    net.IP
	IsPublic   bool
	IsLoopback bool
	IsV4       bool
	RemoteIP   net.IP
	Error      *FindError
}

func (self IPAddrMap) HasNAT() bool {
	if self.RemoteIP == nil {
		return false
	}
	return !self.LocalIP.Equal(self.RemoteIP)
}

func (self IPAddrMap) IPNatStr() string {
	if self.RemoteIP == nil {
		if self.LocalIP == nil {
			return "<no ip>"
		}
		return self.LocalIP.String() + "(not public)"
	}
	if self.LocalIP == nil || self.LocalIP.Equal(self.RemoteIP) {
		return self.RemoteIP.String()
	}

	return self.LocalIP.String() + " --NAT--> " + self.RemoteIP.String()
}

type FindError struct {
	IP              net.IP
	NotOnline       bool
	BadResponse     bool
	BadResponseCode int
	Err             error
}

func (self *FindError) Error() string {
	if self.NotOnline {
		return fmt.Sprintf("IP: %s is not connected to the internet", self.IP.String())
	}
	if self.BadResponseCode != 0 {
		return fmt.Sprintf("IP: %s got code %d from %s", self.IP.String(), self.BadResponseCode, IPFindSite)
	}
	return fmt.Sprintf("IP: %s unknown connection error: %s", self.IP.String(), self.Err.Error())
}

func (self *FindError) Connected() bool {
	if self.BadResponse || self.BadResponseCode != 0 {
		return true
	}
	return false
}

func FindPublicIPFor(addr net.Addr, dialer *net.Dialer) (net.IP, *FindError) {
	if dialer == nil {
		dialer = &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
			DualStack: false,
		}
	}
	var ip net.IP
	switch v := addr.(type) {
	case *net.IPNet:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	}
	oldLocal := dialer.LocalAddr
	defer func() { dialer.LocalAddr = oldLocal }()

	ipAddr := &net.TCPAddr{ip, 0, ""}
	dialer.LocalAddr = ipAddr

	client := http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       15 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 12 * time.Second,
	}}
	res, err := client.Get(IPFindSite)
	if err != nil {
		if urlErr, ok := err.(*url.Error); ok {
			if _, ok := urlErr.Err.(*net.OpError); ok {
				return nil, &FindError{IP: ip, NotOnline: true, Err: err}
			}
		}
		return nil, &FindError{IP: ip, Err: err}
	}
	if res.StatusCode != 200 {
		return nil, &FindError{IP: ip, BadResponseCode: res.StatusCode}
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, &FindError{IP: ip, BadResponse: true, Err: err}
	}

	pubIPStr := strings.TrimSpace(string(body))
	pubIP := net.ParseIP(pubIPStr)
	if pubIP == nil {
		return nil, &FindError{IP: ip, BadResponse: true, Err: errors.New("Unexpected response string: '" + pubIPStr + "' (not an IP)")}
	}
	return pubIP, nil
}

// string to try and make short work of common groups
func FilterToString(filter int) string {
	allv4 := WANT_PUBLIC_V4 | WANT_PRIVATE_V4 | WANT_LOOPBACK_V4
	allv6 := WANT_PUBLIC_V6 | WANT_PRIVATE_V6 | WANT_LOOPBACK_V6
	v4want := filter & allv4
	v6want := filter & allv6

	if v6want == 0 {
		if v4want == 0 {
			return "nothing"
		}
		if v4want == allv4 {
			if filter&WANT_LIVE_IP != 0 {
				return "any live v4"
			}
			return "v4"
		}
		if v4want == WANT_PUBLIC_V4 {
			if filter&WANT_LIVE_IP != 0 {
				return "live public v4"
			}
			return "public v4"
		}
		if v4want == WANT_PRIVATE_V4 {
			if filter&WANT_LIVE_IP != 0 {
				return "live private v4"
			}
			return "private v4"
		}
		if v4want == WANT_LOOPBACK_V4 {
			if filter&WANT_LIVE_IP != 0 {
				return "live loopback v4"
			}
			return "loopback v4"
		}
		// we have two of three
		if v4want&WANT_PUBLIC_V4 != 0 {
			need := ""
			if v4want&WANT_PRIVATE_V4 != 0 {
				need = "non-loopback v4"
			} else {
				need = "non-private v4"
			}
			if filter&WANT_LIVE_IP != 0 {
				return "live " + need
			}
			return need
		} else if filter&WANT_LIVE_IP != 0 {
			return "live non-public v4"
		} else {
			return "non-public v4"
		}
	} else if v4want == 0 {
		if v6want == allv6 {
			if filter&WANT_LIVE_IP != 0 {
				return "live v6"
			}
			return "v4"
		}
		if v6want == WANT_PUBLIC_V6 {
			if filter&WANT_LIVE_IP != 0 {
				return "live public v6"
			}
			return "public v6"
		}
		if v6want == WANT_PRIVATE_V6 {
			if filter&WANT_LIVE_IP != 0 {
				return "live private v6"
			}
			return "private v6"
		}
		if v6want == WANT_LOOPBACK_V6 {
			if filter&WANT_LIVE_IP != 0 {
				return "live loopback v6"
			}
			return "loopback v6"
		}
		// we have two of three
		if v6want&WANT_PUBLIC_V6 != 0 {
			need := ""
			if v6want&WANT_PRIVATE_V6 != 0 {
				need = "non-loopback v6"
			} else {
				need = "non-private v6"
			}
			if filter&WANT_LIVE_IP != 0 {
				return "live " + need
			}
			return need
		} else if filter&WANT_LIVE_IP != 0 {
			return "live non-public v6"
		} else {
			return "non-public v6"
		}
	}

	if v4want == allv4 && v6want == allv6 {
		if filter&WANT_LIVE_IP != 0 {
			return "live"
		}
		return "any"
	}

	if filter&WANT_PUBLIC_V4 != 0 &&
		filter&WANT_PUBLIC_V6 != 0 &&
		filter&WANT_PRIVATE_V4 != 0 &&
		filter&WANT_PRIVATE_V6 != 0 {
		if filter&WANT_LIVE_IP != 0 {
			return "live non-loopback"
		}
		return "non-loopback"
	}

	if filter&WANT_PUBLIC_V4 != 0 &&
		filter&WANT_PUBLIC_V6 != 0 &&
		filter&WANT_LOOPBACK_V4 != 0 &&
		filter&WANT_LOOPBACK_V6 != 0 {
		if filter&WANT_LIVE_IP != 0 {
			return "live non-private"
		}
		return "non-private"
	}

	if filter&WANT_PRIVATE_V4 != 0 &&
		filter&WANT_PRIVATE_V6 != 0 &&
		filter&WANT_LOOPBACK_V4 != 0 &&
		filter&WANT_LOOPBACK_V6 != 0 {
		if filter&WANT_LIVE_IP != 0 {
			return "live non-public"
		}
		return "non-public"
	}

	if filter&WANT_PRIVATE_V4 != 0 &&
		filter&WANT_PRIVATE_V6 != 0 {
		if filter&WANT_LIVE_IP != 0 {
			return "live private"
		}
		return "private"
	}

	if filter&WANT_PUBLIC_V4 != 0 &&
		filter&WANT_PUBLIC_V6 != 0 {
		if filter&WANT_LIVE_IP != 0 {
			return "live public"
		}
		return "public"
	}

	if filter&WANT_LOOPBACK_V4 != 0 &&
		filter&WANT_LOOPBACK_V6 != 0 {
		if filter&WANT_LIVE_IP != 0 {
			return "live loopback"
		}
		return "loopback"
	}

	if filter&WANT_PUBLIC_V4 != 0 &&
		filter&WANT_PRIVATE_V4 != 0 &&
		filter&WANT_LOOPBACK_V4 != 0 {
		if filter&WANT_LIVE_IP != 0 {
			return "live v4"
		}
		return "v4"
	}

	if filter&WANT_PUBLIC_V6 != 0 &&
		filter&WANT_PRIVATE_V6 != 0 &&
		filter&WANT_LOOPBACK_V6 != 0 {
		if filter&WANT_LIVE_IP != 0 {
			return "live v6"
		}
		return "v6"
	}
	v4W := FilterToString(v4want)
	v6W := FilterToString(v4want)
	out := ""
	if filter&WANT_LIVE_IP != 0 {
		out = "live "
	}
	return out + v4W + " or " + v6W
}

func FilterInterfaceIPs(iface net.Interface, want int) ([]IPAddrMap, error) {
	addrs, err := iface.Addrs()
	// handle err
	if err != nil {
		return nil, err
	}
	wantPubV4 := want & WANT_PUBLIC_V4
	wantPubV6 := want & WANT_PUBLIC_V6
	wantPriV4 := want & WANT_PRIVATE_V4
	wantPriV6 := want & WANT_PRIVATE_V6
	wantLoV4 := want & WANT_LOOPBACK_V4
	wantLoV6 := want & WANT_LOOPBACK_V6
	wantLive := want & WANT_LIVE_IP

	ipAddrs := make([]IPAddrMap, 0, len(addrs))
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		entry := IPAddrMap{Local: addr, LocalIP: ip}
		entry.IsPublic = IsPublicIP(ip)
		entry.IsV4 = true
		if ip.To4() == nil {
			entry.IsV4 = false
		}
		if ip.IsLoopback() {
			entry.IsLoopback = true
			if (wantLoV6 != 0 && !entry.IsV4) || (wantLoV4 != 0 && entry.IsV4) {
				ipAddrs = append(ipAddrs, entry)
			}
			continue
		}

		if entry.IsPublic {
			if (wantPubV6 != 0 && !entry.IsV4) || (wantPubV4 != 0 && entry.IsV4) {
				if wantLive != 0 {
					entry.RemoteIP, entry.Error = FindPublicIPFor(addr, nil)
					if entry.Error != nil && !entry.Error.Connected() {
						continue
					}
				}
				ipAddrs = append(ipAddrs, entry)
			}
			continue
		}
		if (wantPriV6 != 0 && !entry.IsV4) || (wantPriV4 != 0 && entry.IsV4) {
			if wantLive != 0 {
				entry.RemoteIP, entry.Error = FindPublicIPFor(addr, nil)
				if entry.Error != nil && !entry.Error.Connected() {
					continue
				}
			}
			ipAddrs = append(ipAddrs, entry)
		}
	}
	return ipAddrs, nil
}
