package geoip

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// EndpointCountries looks up the public addresses of one probe batch. The
// full country database is streamed once; only IPs in the batch are indexed.
// A hostname has a country only when every returned address agrees.
func EndpointCountries(ctx context.Context, path string, hosts []string) map[string]string {
	if path == "" || len(hosts) == 0 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	const maxBytes = 64 << 20
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > maxBytes {
		return nil
	}

	addresses := resolveEndpoints(ctx, hosts)
	return lookupEndpoints(ctx, bufio.NewReader(io.LimitReader(f, st.Size())), addresses)
}

func resolveEndpoints(ctx context.Context, hosts []string) map[string][]netip.Addr {
	resolved := make(map[string][]netip.Addr)
	jobs := make(chan string, len(hosts))
	for _, host := range hosts {
		if host == "" {
			continue
		}
		if _, exists := resolved[host]; exists {
			continue
		}
		resolved[host] = nil
		if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
			resolved[host] = []netip.Addr{ip.Unmap()}
		} else {
			jobs <- host
		}
	}
	close(jobs)
	var mu sync.Mutex
	var wg sync.WaitGroup
	// Limit how long a failing DNS resolver can delay a whole probe batch.
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	for range min(4, len(jobs)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				if ctx.Err() != nil {
					return
				}
				attempt, stop := context.WithTimeout(ctx, 1500*time.Millisecond)
				ips, err := net.DefaultResolver.LookupNetIP(attempt, "ip", host)
				stop()
				if err == nil && len(ips) > 0 {
					mu.Lock()
					resolved[host] = ips
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	return resolved
}

func lookupEndpoints(ctx context.Context, r *bufio.Reader, hosts map[string][]netip.Addr) map[string]string {
	matches := map[netip.Addr]string{}
	var needles []netip.Addr
	for _, ips := range hosts {
		for _, ip := range ips {
			ip = ip.Unmap()
			if _, seen := matches[ip]; !seen && ip.IsGlobalUnicast() && !ip.IsPrivate() {
				matches[ip] = ""
				needles = append(needles, ip)
			}
		}
	}
	if len(needles) == 0 {
		return nil
	}
	sort.Slice(needles, func(i, j int) bool { return needles[i].Less(needles[j]) })
	// GeoIPList consists of repeated GeoIP messages at field 1. Only one
	// message's CIDRs occupy memory at a time, including on IPv6-heavy files.
	var entry []byte
	for ctx.Err() == nil {
		key, err := binary.ReadUvarint(r)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || key != 10 {
			return nil
		}
		n, err := binary.ReadUvarint(r)
		if err != nil || n > 64<<20 {
			return nil
		}
		if uint64(cap(entry)) < n {
			entry = make([]byte, n)
		}
		entry = entry[:n]
		if _, err := io.ReadFull(r, entry); err != nil {
			return nil
		}
		code := countryCodeOf(entry)
		if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
			continue
		}
		// An inverse group denotes every IP outside its list.
		inverse := false
		if !walk(entry, func(f, w int, v uint64, _ []byte) bool {
			if f == 3 && w == 0 && v != 0 {
				inverse = true
			}
			return true
		}) {
			return nil
		}
		if inverse {
			continue
		}
		valid := true
		if !walk(entry, func(f, w int, _ uint64, cidr []byte) bool {
			if f != 2 || w != 2 {
				return true
			}
			prefix := endpointPrefix(cidr)
			if !prefix.IsValid() {
				valid = false
				return false
			}
			start := sort.Search(len(needles), func(i int) bool { return !needles[i].Less(prefix.Addr()) })
			for _, item := range needles[start:] {
				if !prefix.Contains(item) {
					break
				}
				if prev := matches[item]; prev != "" && prev != code {
					matches[item] = "?"
				} else {
					matches[item] = code
				}
			}
			return true
		}) || !valid {
			return nil
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	result := make(map[string]string)
	for host, ips := range hosts {
		var country string
		for _, ip := range ips {
			code := matches[ip.Unmap()]
			if len(code) != 2 || country != "" && code != country {
				country = ""
				break
			}
			country = code
		}
		if country != "" {
			result[host] = country
		}
	}
	return result
}

func endpointPrefix(data []byte) netip.Prefix {
	var ip netip.Addr
	var bits uint64
	ok := walk(data, func(field, wire int, value uint64, b []byte) bool {
		switch {
		case field == 1 && wire == 2:
			ip, _ = netip.AddrFromSlice(b)
		case field == 2 && wire == 0:
			bits = value
		}
		return true
	})
	if !ok || !ip.IsValid() || bits > uint64(ip.BitLen()) {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(ip, int(bits)).Masked()
}
