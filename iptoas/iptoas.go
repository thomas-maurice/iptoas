/*
    DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                       Version 2, December 2004

    Copyright (C) 2016 Thomas Maurice <thomas@maurice.fr>

    Everyone is permitted to copy and distribute verbatim or modified
    copies of this license document, and changing it is allowed as long
    as the name is changed.

               DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
      TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

     0. You just DO WHAT THE FUCK YOU WANT TO.
*/

package iptoas

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strconv"
	"strings"
)

var (
	InvalidIPAddressError = errors.New("Invalid IP address provided")
	NoASNFoundError       = errors.New("No ASN was found")
)

// AddressInfo stucture
type AddressInfo struct {
	ASNumber      int64  `json:"as_number,omitempty"`
	Network       string `json:"network,omitempty"`
	CountryCode   string `json:"country_code,omitempty"`
	ASName        string `json:"as_name,omitempty"`
	ASCountryCode string `json:"as_country_code,omitempty"`
}

// IPToASNResolver structure
type IPToASNResolver struct {
	DNSResolver string
}

// Returns a new resolver
func NewIPToASNResolver(DNSResolver string) *IPToASNResolver {
	return &IPToASNResolver{
		DNSResolver: DNSResolver,
	}
}

// Function taken from https://libsecure.so/t/golang-ip-reversal/146 and adapted
// Reverses the IP given to it
// 127.0.0.1 -> 1.0.0.127
// 2001:4130:8:67d2::3363 -> 3.6.3.3.0.0.0.0.0.0.0.0.0.0.0.0.2.d.7.6.8.0.0.0.0.d.1.4.1.0.0.2
// It returns:
// * The reversed IP
// * True if that's an IPv6
// * an error if something occured
func ReverseIP(IP string) (string, bool, error) {
	var StringSplitIP []string
	var isv6 bool

	parsedIP := net.ParseIP(IP)
	if parsedIP == nil {
		return "", false, InvalidIPAddressError
	}

	if parsedIP.To4() != nil { // Check for an IPv4 address
		StringSplitIP = strings.Split(IP, ".") // Split into 4 groups
		for x, y := 0, len(StringSplitIP)-1; x < y; x, y = x+1, y-1 {
			StringSplitIP[x], StringSplitIP[y] = StringSplitIP[y], StringSplitIP[x] // Reverse the groups
		}
	} else {
		isv6 = true
		StringSplitIP = strings.Split(IP, ":") // Split into however many groups

		/* Due to IPv6 lookups being different than IPv4 we have an extra check here
		We have to expand the :: and do 0-padding if there are less than 4 digits */
		for key := range StringSplitIP {
			if len(StringSplitIP[key]) == 0 { // Found the ::
				StringSplitIP[key] = strings.Repeat("0000", 8-strings.Count(IP, ":"))
			} else if len(StringSplitIP[key]) < 4 { // 0-padding needed
				StringSplitIP[key] = strings.Repeat("0", 4-len(StringSplitIP[key])) + StringSplitIP[key]
			}
		}

		// We have to join what we have and split it again to get all the letters split individually
		StringSplitIP = strings.Split(strings.Join(StringSplitIP, ""), "")

		for x, y := 0, len(StringSplitIP)-1; x < y; x, y = x+1, y-1 {
			StringSplitIP[x], StringSplitIP[y] = StringSplitIP[y], StringSplitIP[x]
		}
	}

	return strings.Join(StringSplitIP, "."), isv6, nil // Return the IP.
}

// Returns the address info associated with an IP address
func (self *IPToASNResolver) GetAddressInfo(ip string) (*AddressInfo, error) {
	var addressInfo AddressInfo
	queryDomain := "origin.asn.cymru.com."
	client := new(dns.Client)
	reversedIP, isV6, err := ReverseIP(ip)
	if err != nil {
		return nil, err
	}

	if isV6 {
		queryDomain = "origin6.asn.cymru.com."
	}

	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{fmt.Sprintf("%s.%s", reversedIP, queryDomain), dns.TypeTXT, dns.ClassINET}
	in, _, err := client.Exchange(msg, self.DNSResolver)
	if err != nil {
		return nil, err
	}
	if len(in.Answer) == 0 {
		return nil, NoASNFoundError
	}
	if t, ok := in.Answer[0].(*dns.TXT); ok {
		if len(t.Txt) == 0 {
			return nil, NoASNFoundError
		}
		infos := strings.Split(t.Txt[0], "|")
		for idx, element := range infos {
			infos[idx] = strings.TrimSpace(element)
		}
		asn, err := strconv.ParseInt(infos[0], 10, 64)
		if err != nil {
			return nil, err
		}
		addressInfo = AddressInfo{
			ASNumber:    asn,
			Network:     infos[1],
			CountryCode: infos[2],
		}

		asName, err := self.GetASName(asn)
		if err != nil {
			return nil, err
		}

		if strings.Contains(asName, ",") {
			addressInfo.ASName = strings.TrimSpace(strings.Split(asName, ",")[0])
			addressInfo.ASCountryCode = strings.TrimSpace(strings.Split(asName, ",")[1])
		} else {
			addressInfo.ASName = strings.TrimSpace(asName)
		}

		return &addressInfo, nil
	}

	return nil, NoASNFoundError
}

// Returns the Name of an AS for the given ASN
func (self *IPToASNResolver) GetASName(asn int64) (string, error) {
	client := new(dns.Client)

	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{fmt.Sprintf("AS%d.asn.cymru.com.", asn), dns.TypeTXT, dns.ClassINET}
	in, _, err := client.Exchange(msg, self.DNSResolver)
	if err != nil {
		return "", err
	}
	if len(in.Answer) == 0 {
		return "", NoASNFoundError
	}
	if t, ok := in.Answer[0].(*dns.TXT); ok {
		if len(t.Txt) == 0 {
			return "", NoASNFoundError
		}
		infos := strings.Split(t.Txt[0], "|")
		for idx, element := range infos {
			infos[idx] = strings.TrimSpace(element)
		}

		return infos[4], nil
	}

	return "", NoASNFoundError
}
