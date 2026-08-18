package geoip

import (
	"net"

	"github.com/oschwald/geoip2-golang"
)

// MaxMindResolver resolves countries via a MaxMind GeoIP2/GeoLite2
// Country-format .mmdb database. The database file itself is not bundled
// with this repository (MaxMind's GeoLite2 requires its own account/
// license and has its own redistribution terms) — operators supply one
// via GEOIP_DB_PATH. See docs/architecture.md.
type MaxMindResolver struct {
	reader *geoip2.Reader
}

// OpenMaxMindResolver opens the .mmdb file at dbPath. The caller must call
// Close when done.
func OpenMaxMindResolver(dbPath string) (*MaxMindResolver, error) {
	reader, err := geoip2.Open(dbPath)
	if err != nil {
		return nil, err
	}
	return &MaxMindResolver{reader: reader}, nil
}

func (r *MaxMindResolver) Close() error {
	return r.reader.Close()
}

func (r *MaxMindResolver) Lookup(ip net.IP) (string, bool) {
	if ip == nil {
		return "", false
	}
	country, err := r.reader.Country(ip)
	if err != nil {
		return "", false
	}
	code := country.Country.IsoCode
	if code == "" {
		return "", false
	}
	return code, true
}

var _ Resolver = (*MaxMindResolver)(nil)
