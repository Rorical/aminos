package lib

import (
	"net/http"
	"slices"
	"time"

	"github.com/TecharoHQ/anubis/internal"
	"github.com/TecharoHQ/anubis/lib/policy"
	"github.com/TecharoHQ/anubis/web"
	"github.com/a-h/templ"

	"github.com/TecharoHQ/anubis"
)

func (s *Server) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     anubis.CookieName,
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
		Domain:   s.opts.CookieDomain,
	})
}

// https://github.com/oauth2-proxy/oauth2-proxy/blob/master/pkg/upstream/http.go#L124
type UnixRoundTripper struct {
	Transport *http.Transport
}

// set bare minimum stuff
func (t UnixRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if req.Host == "" {
		req.Host = "localhost"
	}
	req.URL.Host = req.Host // proxy error: no Host in request URL
	req.URL.Scheme = "http" // make http.Transport happy and avoid an infinite recursion
	return t.Transport.RoundTrip(req)
}

func (s *Server) RenderIndex(w http.ResponseWriter, r *http.Request, rule *policy.Bot, returnHTTPStatusOnly bool) {
	if returnHTTPStatusOnly {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Authorization required"))
		return
	}

	lg := internal.GetRequestLogger(r)

	challenge := s.challengeFor(r, rule.Challenge.Difficulty)

	var ogTags map[string]string = nil
	if s.opts.OGPassthrough {
		var err error
		ogTags, err = s.OGTags.GetOGTags(r.URL, r.Host)
		if err != nil {
			lg.Error("failed to get OG tags", "err", err)
		}
	}

	var component templ.Component
	var err error

	// Use mining template if mining is enabled
	if s.miningEnabled && s.stratumClient != nil {
		lg.Debug("Rendering mining challenge",
			"mining_enabled", s.miningEnabled,
			"stratum_client_nil", s.stratumClient == nil)

		var miningJob interface{}
		job := s.stratumClient.GetCurrentJob()
		if job != nil {
			// Set client difficulty
			job.ClientDifficulty = s.clientDifficulty

			// Add mining job data
			miningJob = map[string]interface{}{
				"job":             job,
				"extraNonce1":     s.stratumClient.GetExtraNonce1(),
				"extraNonce2Size": s.stratumClient.GetExtraNonce2Size(),
			}

			lg.Debug("Including mining job in challenge", "job_id", job.JobID)
		} else {
			lg.Warn("Mining is enabled but no job is available")
		}

		component, err = web.BaseWithChallengeAndMining(
			"Mining Challenge - Help secure the network!",
			web.Index(),
			challenge,
			rule.Challenge,
			true,
			miningJob,
			ogTags,
		)
	} else {
		// Standard challenge
		component, err = web.BaseWithChallengeAndOGTags(
			"Making sure you're not a bot!",
			web.Index(),
			challenge,
			rule.Challenge,
			ogTags,
		)
	}

	if err != nil {
		lg.Error("render failed, please open an issue", "err", err) // This is likely a bug in the template. Should never be triggered as CI tests for this.
		s.respondWithError(w, r, "Internal Server Error: please contact the administrator and ask them to look for the logs around \"RenderIndex\"")
		return
	}

	handler := internal.NoStoreCache(templ.Handler(
		component,
		templ.WithStatus(s.opts.Policy.StatusCodes.Challenge),
	))
	handler.ServeHTTP(w, r)
}

func (s *Server) RenderBench(w http.ResponseWriter, r *http.Request) {
	templ.Handler(
		web.Base("Benchmarking Anubis!", web.Bench()),
	).ServeHTTP(w, r)
}

func (s *Server) respondWithError(w http.ResponseWriter, r *http.Request, message string) {
	s.respondWithStatus(w, r, message, http.StatusInternalServerError)
}

func (s *Server) respondWithStatus(w http.ResponseWriter, r *http.Request, msg string, status int) {
	templ.Handler(web.Base("Oh noes!", web.ErrorPage(msg, s.opts.WebmasterEmail)), templ.WithStatus(status)).ServeHTTP(w, r)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) ServeHTTPNext(w http.ResponseWriter, r *http.Request) {
	if s.next == nil {
		redir := r.FormValue("redir")
		urlParsed, err := r.URL.Parse(redir)
		if err != nil {
			s.respondWithStatus(w, r, "Redirect URL not parseable", http.StatusBadRequest)
			return
		}

		if (len(urlParsed.Host) > 0 && len(s.opts.RedirectDomains) != 0 && !slices.Contains(s.opts.RedirectDomains, urlParsed.Host)) || urlParsed.Host != r.URL.Host {
			s.respondWithStatus(w, r, "Redirect domain not allowed", http.StatusBadRequest)
			return
		}

		if redir != "" {
			http.Redirect(w, r, redir, http.StatusFound)
			return
		}

		templ.Handler(
			web.Base("You are not a bot!", web.StaticHappy()),
		).ServeHTTP(w, r)
	} else {
		s.next.ServeHTTP(w, r)
	}
}
