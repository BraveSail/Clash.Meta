package sing_tun

import (
	"strings"

	"golang.org/x/exp/slices"
)

func systemDNSSearchDomainArgs(tunName string, searchDomains []string) []string {
	args := []string{"domain", tunName, "~."}
	return append(args, normalizeSearchDomains(searchDomains)...)
}

// normalizeSearchDomains lowercases, trims and dedupes the search domains a
// configuration lists, so the same domain written twice is configured once.
func normalizeSearchDomains(domains []string) []string {
	normalized := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		domain = strings.TrimRight(domain, ".")
		if domain == "" || domain == "~" {
			continue
		}
		normalized = append(normalized, domain)
	}
	slices.Sort(normalized)
	return slices.Compact(normalized)
}
