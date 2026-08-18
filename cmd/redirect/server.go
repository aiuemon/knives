package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/aiuemon/knives/internal/cache"
	"github.com/aiuemon/knives/internal/geoip"
	"github.com/aiuemon/knives/internal/storage"
)

const clickStreamName = "clicks"

type server struct {
	cache       *cache.Cache
	store       *storage.RedirectStore
	redisClient *redis.Client
	domainID    uuid.UUID
	ipHashSalt  string
	limiter     *ipRateLimiter
	geoResolver geoip.Resolver
}

// cachedTarget is the JSON value stored in cache.Cache for one short_code:
// the redirect target plus the short_url_id needed for click logging, so a
// cache hit never has to query PostgreSQL just to attribute a click.
type cachedTarget struct {
	ID      uuid.UUID `json:"id"`
	LongURL string    `json:"long_url"`
}

func (s *server) routes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Get("/{code}", s.handleRedirect)
	return r
}

func (s *server) handleRedirect(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.limiter.allow(ip) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	code := chi.URLParam(r, "code")
	ctx := r.Context()
	cacheKey := s.domainID.String() + ":" + code

	if raw, ok, err := s.cache.Get(ctx, cacheKey); err != nil {
		slog.Error("cache lookup failed, falling back to storage", "error", err)
	} else if ok {
		var target cachedTarget
		if err := json.Unmarshal([]byte(raw), &target); err == nil {
			s.recordClickAsync(target.ID, r)
			http.Redirect(w, r, target.LongURL, http.StatusFound)
			return
		}
		slog.Error("corrupt cache value, falling back to storage", "key", cacheKey)
	}

	id, longURL, err := s.store.FindRedirectTarget(ctx, s.domainID, code)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if raw, err := json.Marshal(cachedTarget{ID: id, LongURL: longURL}); err != nil {
		slog.Error("cache value encode failed", "error", err)
	} else if err := s.cache.Set(ctx, cacheKey, string(raw), 0); err != nil {
		slog.Error("cache populate failed", "error", err)
	}

	s.recordClickAsync(id, r)
	http.Redirect(w, r, longURL, http.StatusFound)
}

// recordClickAsync pushes the click onto the Redis Stream after the
// redirect response has already been written, so click logging never adds
// latency to the hot path (6節-4). Failures are logged, not surfaced: a
// dropped click event must never turn into a broken redirect.
func (s *server) recordClickAsync(shortURLID uuid.UUID, r *http.Request) {
	values := buildClickValues(shortURLID, r, s.ipHashSalt, s.geoResolver)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.redisClient.XAdd(ctx, &redis.XAddArgs{Stream: clickStreamName, Values: values}).Err(); err != nil {
			slog.Error("click stream push failed", "error", err)
		}
	}()
}

// buildClickValues assembles the Redis Stream entry for one click. Kept
// separate from recordClickAsync's goroutine dispatch so it's testable
// without a real Redis connection.
func buildClickValues(shortURLID uuid.UUID, r *http.Request, ipHashSalt string, geoResolver geoip.Resolver) map[string]any {
	ip := clientIP(r)
	// 国の解決はここでしか行えない: ip_hashは不可逆なため、ハッシュ化
	// する前の生IPを使えるのはこのリクエスト処理中だけ(internal/geoip)。
	countryCode, _ := geoResolver.Lookup(net.ParseIP(ip))

	return map[string]any{
		"short_url_id":  shortURLID.String(),
		"clicked_at":    time.Now().UTC().Format(time.RFC3339Nano),
		"referrer_host": refererHost(r.Referer()),
		"user_agent":    r.UserAgent(),
		"ip_hash":       hashIP(ip, ipHashSalt),
		"country_code":  countryCode,
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// refererHost keeps only the referrer's host, matching click_events'
// privacy-conscious "referrer_host only, never the full URL" design.
func refererHost(referer string) string {
	if referer == "" {
		return ""
	}
	u, err := url.Parse(referer)
	if err != nil {
		return ""
	}
	return u.Host
}

func hashIP(ip, salt string) string {
	sum := sha256.Sum256([]byte(salt + ip))
	return hex.EncodeToString(sum[:])
}
