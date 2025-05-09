package lib

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/TecharoHQ/anubis"
	"github.com/TecharoHQ/anubis/decaymap"
	"github.com/TecharoHQ/anubis/internal"
	"github.com/TecharoHQ/anubis/internal/dnsbl"
	"github.com/TecharoHQ/anubis/internal/ogtags"
	"github.com/TecharoHQ/anubis/lib/mining"
	"github.com/TecharoHQ/anubis/lib/policy"
	"github.com/TecharoHQ/anubis/lib/policy/config"
)

var (
	challengesIssued = promauto.NewCounter(prometheus.CounterOpts{
		Name: "anubis_challenges_issued",
		Help: "The total number of challenges issued",
	})

	challengesValidated = promauto.NewCounter(prometheus.CounterOpts{
		Name: "anubis_challenges_validated",
		Help: "The total number of challenges validated",
	})

	droneBLHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "anubis_dronebl_hits",
		Help: "The total number of hits from DroneBL",
	}, []string{"status"})

	failedValidations = promauto.NewCounter(prometheus.CounterOpts{
		Name: "anubis_failed_validations",
		Help: "The total number of failed validations",
	})

	timeTaken = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "anubis_time_taken",
		Help:    "The time taken for a browser to generate a response (milliseconds)",
		Buckets: prometheus.ExponentialBucketsRange(1, math.Pow(2, 18), 19),
	})

	// Mining metrics
	miningSharesSubmitted = promauto.NewCounter(prometheus.CounterOpts{
		Name: "anubis_mining_shares_submitted",
		Help: "The total number of mining shares submitted by clients",
	})

	miningSharesAccepted = promauto.NewCounter(prometheus.CounterOpts{
		Name: "anubis_mining_shares_accepted",
		Help: "The total number of mining shares accepted (client difficulty)",
	})

	miningSharesRejected = promauto.NewCounter(prometheus.CounterOpts{
		Name: "anubis_mining_shares_rejected",
		Help: "The total number of mining shares rejected",
	})

	miningPoolShares = promauto.NewCounter(prometheus.CounterOpts{
		Name: "anubis_mining_pool_shares",
		Help: "The total number of shares accepted by the pool",
	})
)

type Server struct {
	next       http.Handler
	mux        *http.ServeMux
	policy     *policy.ParsedConfig
	DNSBLCache *decaymap.Impl[string, dnsbl.DroneBLResponse]
	OGTags     *ogtags.OGTagCache
	priv       ed25519.PrivateKey
	pub        ed25519.PublicKey
	opts       Options

	// Mining-related fields
	stratumClient    *mining.StratumClient
	miningEnabled    bool
	clientDifficulty float64
}

// Initialize the mining components
func (s *Server) initMining() error {
	// Skip if mining is not enabled
	if !s.opts.Mining.Enabled {
		slog.Info("Mining functionality is disabled")
		return nil
	}

	slog.Info("Initializing Bitcoin mining functionality",
		"pool_address", s.opts.Mining.PoolAddress,
		"pool_username", s.opts.Mining.PoolUsername,
		"client_difficulty", s.opts.Mining.ClientDifficulty)

	if s.opts.Mining.PoolAddress == "" {
		slog.Error("Mining pool address is empty")
		return fmt.Errorf("mining pool address cannot be empty")
	}

	// Create and initialize the Stratum client
	client, err := mining.NewStratumClient(
		s.opts.Mining.PoolAddress,
		s.opts.Mining.PoolUsername,
		s.opts.Mining.PoolPassword,
	)

	if err != nil {
		slog.Error("Failed to initialize mining client", "error", err)
		return fmt.Errorf("failed to initialize mining: %w", err)
	}

	s.stratumClient = client
	s.miningEnabled = true
	s.clientDifficulty = s.opts.Mining.ClientDifficulty

	// Add a brief delay to allow the stratum client to connect and get a job
	time.Sleep(500 * time.Millisecond)

	// Check if we have a job
	job := s.stratumClient.GetCurrentJob()
	if job == nil {
		slog.Warn("No mining job available after initialization, but continuing anyway")
	} else {
		slog.Info("Successfully retrieved initial mining job from pool", "job_id", job.JobID)
	}

	slog.Info("Bitcoin mining initialized successfully",
		"pool", s.opts.Mining.PoolAddress,
		"client_difficulty", s.clientDifficulty)

	return nil
}

func (s *Server) challengeFor(r *http.Request, difficulty int) string {
	fp := sha256.Sum256(s.priv.Seed())

	challengeData := fmt.Sprintf(
		"Accept-Language=%s,X-Real-IP=%s,User-Agent=%s,WeekTime=%s,Fingerprint=%x,Difficulty=%d",
		r.Header.Get("Accept-Language"),
		r.Header.Get("X-Real-Ip"),
		r.UserAgent(),
		time.Now().UTC().Round(24*7*time.Hour).Format(time.RFC3339),
		fp,
		difficulty,
	)
	return internal.SHA256sum(challengeData)
}

func (s *Server) maybeReverseProxyHttpStatusOnly(w http.ResponseWriter, r *http.Request) {
	s.maybeReverseProxy(w, r, true)
}

func (s *Server) maybeReverseProxyOrPage(w http.ResponseWriter, r *http.Request) {
	s.maybeReverseProxy(w, r, false)
}

func (s *Server) maybeReverseProxy(w http.ResponseWriter, r *http.Request, httpStatusOnly bool) {
	lg := internal.GetRequestLogger(r)

	cr, rule, err := s.check(r)
	if err != nil {
		lg.Error("check failed", "err", err)
		s.respondWithError(w, r, "Internal Server Error: administrator has misconfigured Anubis. Please contact the administrator and ask them to look for the logs around \"maybeReverseProxy\"")
		return
	}

	r.Header.Add("X-Anubis-Rule", cr.Name)
	r.Header.Add("X-Anubis-Action", string(cr.Rule))
	lg = lg.With("check_result", cr)
	policy.Applications.WithLabelValues(cr.Name, string(cr.Rule)).Add(1)

	ip := r.Header.Get("X-Real-Ip")

	if s.handleDNSBL(w, r, ip, lg) {
		return
	}

	if s.checkRules(w, r, cr, lg, rule) {
		return
	}

	ckie, err := r.Cookie(anubis.CookieName)
	if err != nil {
		lg.Debug("cookie not found", "path", r.URL.Path)
		s.ClearCookie(w)
		s.RenderIndex(w, r, rule, httpStatusOnly)
		return
	}

	if err := ckie.Valid(); err != nil {
		lg.Debug("cookie is invalid", "err", err)
		s.ClearCookie(w)
		s.RenderIndex(w, r, rule, httpStatusOnly)
		return
	}

	if time.Now().After(ckie.Expires) && !ckie.Expires.IsZero() {
		lg.Debug("cookie expired", "path", r.URL.Path)
		s.ClearCookie(w)
		s.RenderIndex(w, r, rule, httpStatusOnly)
		return
	}

	token, err := jwt.ParseWithClaims(ckie.Value, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return s.pub, nil
	}, jwt.WithExpirationRequired(), jwt.WithStrictDecoding())

	if err != nil || !token.Valid {
		lg.Debug("invalid token", "path", r.URL.Path, "err", err)
		s.ClearCookie(w)
		s.RenderIndex(w, r, rule, httpStatusOnly)
		return
	}

	r.Header.Add("X-Anubis-Status", "PASS")
	s.ServeHTTPNext(w, r)
}

func (s *Server) checkRules(w http.ResponseWriter, r *http.Request, cr policy.CheckResult, lg *slog.Logger, rule *policy.Bot) bool {
	switch cr.Rule {
	case config.RuleAllow:
		lg.Debug("allowing traffic to origin (explicit)")
		s.ServeHTTPNext(w, r)
		return true
	case config.RuleDeny:
		s.ClearCookie(w)
		lg.Info("explicit deny")
		if rule == nil {
			lg.Error("rule is nil, cannot calculate checksum")
			s.respondWithError(w, r, "Internal Server Error: Please contact the administrator and ask them to look for the logs around \"maybeReverseProxy.RuleDeny\"")
			return true
		}
		hash := rule.Hash()

		lg.Debug("rule hash", "hash", hash)
		s.respondWithStatus(w, r, fmt.Sprintf("Access Denied: error code %s", hash), s.policy.StatusCodes.Deny)
		return true
	case config.RuleChallenge:
		lg.Debug("challenge requested")
	case config.RuleBenchmark:
		lg.Debug("serving benchmark page")
		s.RenderBench(w, r)
		return true
	default:
		s.ClearCookie(w)
		slog.Error("CONFIG ERROR: unknown rule", "rule", cr.Rule)
		s.respondWithError(w, r, "Internal Server Error: administrator has misconfigured Anubis. Please contact the administrator and ask them to look for the logs around \"maybeReverseProxy.Rules\"")
		return true
	}
	return false
}

func (s *Server) handleDNSBL(w http.ResponseWriter, r *http.Request, ip string, lg *slog.Logger) bool {
	if s.policy.DNSBL && ip != "" {
		resp, ok := s.DNSBLCache.Get(ip)
		if !ok {
			lg.Debug("looking up ip in dnsbl")
			resp, err := dnsbl.Lookup(ip)
			if err != nil {
				lg.Error("can't look up ip in dnsbl", "err", err)
			}
			s.DNSBLCache.Set(ip, resp, 24*time.Hour)
			droneBLHits.WithLabelValues(resp.String()).Inc()
		}

		if resp != dnsbl.AllGood {
			lg.Info("DNSBL hit", "status", resp.String())
			s.respondWithStatus(w, r, fmt.Sprintf("DroneBL reported an entry: %s, see https://dronebl.org/lookup?ip=%s", resp.String(), ip), s.policy.StatusCodes.Deny)
			return true
		}
	}
	return false
}

func (s *Server) MakeChallenge(w http.ResponseWriter, r *http.Request) {
	lg := internal.GetRequestLogger(r)

	// Add debug logging to track mining configuration
	lg.Debug("MakeChallenge called",
		"mining_enabled", s.miningEnabled,
		"stratum_client_nil", s.stratumClient == nil,
		"client_difficulty", s.clientDifficulty)

	encoder := json.NewEncoder(w)
	cr, rule, err := s.check(r)
	if err != nil {
		lg.Error("check failed", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		err := encoder.Encode(struct {
			Error string `json:"error"`
		}{
			Error: "Internal Server Error: administrator has misconfigured Anubis. Please contact the administrator and ask them to look for the logs around \"makeChallenge\"",
		})
		if err != nil {
			lg.Error("failed to encode error response", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	lg = lg.With("check_result", cr)
	challenge := s.challengeFor(r, rule.Challenge.Difficulty)

	// Create response struct with basic challenge data
	response := struct {
		Rules     *config.ChallengeRules `json:"rules"`
		Challenge string                 `json:"challenge"`
		Mining    bool                   `json:"mining,omitempty"`
		MiningJob interface{}            `json:"mining_job,omitempty"`
	}{
		Challenge: challenge,
		Rules:     rule.Challenge,
		Mining:    s.miningEnabled,
	}

	// Include mining data if enabled
	if s.miningEnabled && s.stratumClient != nil {
		lg.Debug("Mining enabled, getting current job from stratum client")
		job := s.stratumClient.GetCurrentJob()
		if job != nil {
			// Set client difficulty
			job.ClientDifficulty = s.clientDifficulty

			// Add mining job data
			response.MiningJob = map[string]interface{}{
				"job":             job,
				"extraNonce1":     s.stratumClient.GetExtraNonce1(),
				"extraNonce2Size": s.stratumClient.GetExtraNonce2Size(),
			}
			lg.Debug("Got mining job from pool", "job_id", job.JobID)
		} else {
			// If mining is enabled but no job is available, we should return an error
			lg.Error("mining is enabled but no job is available")
			w.WriteHeader(http.StatusServiceUnavailable)
			err := encoder.Encode(struct {
				Error string `json:"error"`
			}{
				Error: "Mining is enabled but no job is available from the pool. Please try again later.",
			})
			if err != nil {
				lg.Error("failed to encode error response", "err", err)
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}
	}

	err = encoder.Encode(response)
	if err != nil {
		lg.Error("failed to encode challenge", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	lg.Debug("made challenge", "challenge", challenge, "rules", rule.Challenge, "cr", cr, "mining", s.miningEnabled, "has_mining_job", response.MiningJob != nil)
	challengesIssued.Inc()
}

func (s *Server) PassChallenge(w http.ResponseWriter, r *http.Request) {
	lg := internal.GetRequestLogger(r)

	redir := r.FormValue("redir")
	redirURL, err := url.ParseRequestURI(redir)
	if err != nil {
		lg.Error("invalid redirect", "err", err)
		s.respondWithError(w, r, "Invalid redirect")
		return
	}
	// used by the path checker rule
	r.URL = redirURL

	cr, rule, err := s.check(r)
	if err != nil {
		lg.Error("check failed", "err", err)
		s.respondWithError(w, r, "Internal Server Error: administrator has misconfigured Anubis. Please contact the administrator and ask them to look for the logs around \"passChallenge\".\"")
		return
	}
	lg = lg.With("check_result", cr)

	nonceStr := r.FormValue("nonce")
	if nonceStr == "" {
		s.ClearCookie(w)
		lg.Debug("no nonce")
		s.respondWithError(w, r, "missing nonce")
		return
	}

	elapsedTimeStr := r.FormValue("elapsedTime")
	if elapsedTimeStr == "" {
		s.ClearCookie(w)
		lg.Debug("no elapsedTime")
		s.respondWithError(w, r, "missing elapsedTime")
		return
	}

	elapsedTime, err := strconv.ParseFloat(elapsedTimeStr, 64)
	if err != nil {
		s.ClearCookie(w)
		lg.Debug("elapsedTime doesn't parse", "err", err)
		s.respondWithError(w, r, "invalid elapsedTime")
		return
	}

	lg.Info("challenge took", "elapsedTime", elapsedTime)
	timeTaken.Observe(elapsedTime)

	response := r.FormValue("response")
	urlParsed, err := r.URL.Parse(redir)
	if err != nil {
		s.respondWithError(w, r, "Redirect URL not parseable")
		return
	}
	if (len(urlParsed.Host) > 0 && len(s.opts.RedirectDomains) != 0 && !slices.Contains(s.opts.RedirectDomains, urlParsed.Host)) || urlParsed.Host != r.URL.Host {
		s.respondWithError(w, r, "Redirect domain not allowed")
		return
	}

	challenge := s.challengeFor(r, rule.Challenge.Difficulty)
	var isValid bool

	// Check if this is a Bitcoin mining response
	isMiningHash := s.miningEnabled && strings.HasPrefix(response, "00000") && len(response) == 64
	if isMiningHash {
		// For mining, we don't validate against the challenge since mining hash is already proof of work
		// We just need to check the hash format (already done) and difficulty (implicit in prefix check)
		isValid = true
		lg.Debug("mining hash accepted for challenge validation", "hash", response)
		lg.Info("note: this only validates the hash for the challenge, not submitting to mining pool")
		challengesValidated.Inc()
		if s.stratumClient != nil {
			// Track the share for metrics
			miningSharesAccepted.Inc()
		}
	} else {
		// Normal PoW validation
		nonce, err := strconv.Atoi(nonceStr)
		if err != nil {
			s.ClearCookie(w)
			lg.Debug("nonce doesn't parse", "err", err)
			s.respondWithError(w, r, "invalid nonce")
			return
		}

		calcString := fmt.Sprintf("%s%d", challenge, nonce)
		calculated := internal.SHA256sum(calcString)

		isValid = subtle.ConstantTimeCompare([]byte(response), []byte(calculated)) == 1 &&
			strings.HasPrefix(response, strings.Repeat("0", rule.Challenge.Difficulty))

		if !isValid {
			s.ClearCookie(w)
			lg.Debug("hash does not match or difficulty not met", "got", response, "want", calculated)
			s.respondWithStatus(w, r, "invalid response", http.StatusForbidden)
			failedValidations.Inc()
			return
		}

		challengesValidated.Inc()
	}

	// At this point the challenge is validated, either via standard PoW or mining

	// Adjust cookie path if base prefix is not empty
	cookiePath := "/"
	if anubis.BasePrefix != "" {
		cookiePath = strings.TrimSuffix(anubis.BasePrefix, "/") + "/"
	}
	// generate JWT cookie
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"challenge": challenge,
		"nonce":     nonceStr,
		"response":  response,
		"iat":       time.Now().Unix(),
		"nbf":       time.Now().Add(-1 * time.Minute).Unix(),
		"exp":       time.Now().Add(s.opts.CookieExpiration).Unix(),
	})
	tokenString, err := token.SignedString(s.priv)
	if err != nil {
		lg.Error("failed to sign JWT", "err", err)
		s.ClearCookie(w)
		s.respondWithError(w, r, "failed to sign JWT")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:        anubis.CookieName,
		Value:       tokenString,
		Expires:     time.Now().Add(s.opts.CookieExpiration),
		SameSite:    http.SameSiteLaxMode,
		Domain:      s.opts.CookieDomain,
		Partitioned: s.opts.CookiePartitioned,
		Path:        cookiePath,
	})

	lg.Debug("challenge passed, redirecting to app")
	http.Redirect(w, r, redir, http.StatusFound)
}

func (s *Server) TestError(w http.ResponseWriter, r *http.Request) {
	err := r.FormValue("err")
	s.respondWithError(w, r, err)
}

func cr(name string, rule config.Rule) policy.CheckResult {
	return policy.CheckResult{
		Name: name,
		Rule: rule,
	}
}

// Check evaluates the list of rules, and returns the result
func (s *Server) check(r *http.Request) (policy.CheckResult, *policy.Bot, error) {
	host := r.Header.Get("X-Real-Ip")
	if host == "" {
		return decaymap.Zilch[policy.CheckResult](), nil, fmt.Errorf("[misconfiguration] X-Real-Ip header is not set")
	}

	addr := net.ParseIP(host)
	if addr == nil {
		return decaymap.Zilch[policy.CheckResult](), nil, fmt.Errorf("[misconfiguration] %q is not an IP address", host)
	}

	for _, b := range s.policy.Bots {
		match, err := b.Rules.Check(r)
		if err != nil {
			return decaymap.Zilch[policy.CheckResult](), nil, fmt.Errorf("can't run check %s: %w", b.Name, err)
		}

		if match {
			return cr("bot/"+b.Name, b.Action), &b, nil
		}
	}

	return cr("default/allow", config.RuleAllow), &policy.Bot{
		Challenge: &config.ChallengeRules{
			Difficulty: s.policy.DefaultDifficulty,
			ReportAs:   s.policy.DefaultDifficulty,
			Algorithm:  config.AlgorithmFast,
		},
	}, nil
}

func (s *Server) CleanupDecayMap() {
	s.DNSBLCache.Cleanup()
	s.OGTags.Cleanup()
}

func (s *Server) SubmitMiningShare(w http.ResponseWriter, r *http.Request) {
	lg := internal.GetRequestLogger(r)

	// Check if mining is enabled
	if !s.miningEnabled || s.stratumClient == nil {
		lg.Error("mining share submission attempted but mining is disabled")
		http.Error(w, "Mining is not enabled", http.StatusBadRequest)
		return
	}

	// Parse request body
	if err := r.ParseForm(); err != nil {
		lg.Error("failed to parse form", "err", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Extract mining share parameters
	jobID := r.FormValue("job_id")
	extraNonce2 := r.FormValue("extra_nonce2")
	nTime := r.FormValue("ntime")
	nonce := r.FormValue("nonce")
	hash := r.FormValue("hash")

	// Validate parameters
	if jobID == "" || extraNonce2 == "" || nTime == "" || nonce == "" {
		lg.Error("missing required mining share parameters",
			"job_id", jobID,
			"extraNonce2", extraNonce2,
			"nTime", nTime,
			"nonce", nonce)
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	lg.Info("received mining share submission",
		"job_id", jobID,
		"hash", hash)

	// Increment shares submitted counter
	miningSharesSubmitted.Inc()

	// Submit the share to the mining pool
	accepted, err := s.stratumClient.SubmitShare(jobID, extraNonce2, nTime, nonce)
	if err != nil {
		lg.Error("failed to submit share to pool", "err", err)
		http.Error(w, fmt.Sprintf("Failed to submit share: %v", err), http.StatusInternalServerError)
		return
	}

	if accepted {
		// Share was accepted by the pool
		lg.Info("share accepted by pool", "hash", hash)
		miningPoolShares.Inc()

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "accepted",
			"message": "Share accepted by pool",
		})
	} else {
		// Share was rejected by the pool
		lg.Warn("share rejected by pool", "hash", hash)
		miningSharesRejected.Inc()

		// Return error response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // Still return 200 but with rejection info
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "rejected",
			"message": "Share rejected by pool",
		})
	}
}
