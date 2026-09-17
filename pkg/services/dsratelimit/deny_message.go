package dsratelimit

import (
	"fmt"
	"time"
)

// denyMessage builds the sentence a throttled user actually reads.
//
// The frontend surfaces err.data.message verbatim (backend_srv.ts:321), so this
// string is the entire explanation someone gets when a panel stops loading.
// "datasource rate limit exceeded" -- what this used to say -- names neither the
// limit that fired, nor its value, nor what to do next, which is every question
// the reader has. It is also the first thing they see after an upgrade that
// introduced throttling where there was none, so an unexplained 429 reads as a
// Grafana fault rather than a quota.
//
// Four things go in, and each one is here because omitting it leaves an
// actionable question unanswered:
//
//   - WHICH LIMIT: personal vs datasource decides who can fix it. Over your own
//     limit, you slow down; a datasource out of quota is shared, and the fix is
//     an operator raising it -- retrying harder does nothing.
//   - WHICH KIND: QPS vs concurrent requests decides *how* to slow down. Fewer
//     requests per second, or fewer at once; a user throttled on concurrency who
//     cuts their rate changes nothing.
//   - THE NUMBER: turns "you are over the limit" into something checkable, and
//     is what gets quoted when asking for more.
//   - WHAT NOW: a concrete wait beats "try again later" -- see the permanent
//     case below for when no wait is enough.
//
// Deliberately absent: the internal key (user ID / IP). It identifies the caller
// to anyone who can read the response, and it is already in the server-side deny
// log where operators need it. See write429's note.
//
// English, matching every other API error in the codebase, and kept to short
// plain words so it survives readers who do not read English comfortably.
type denyKind int

const (
	// denyKindQPS is the token-bucket layer: requests per second.
	denyKindQPS denyKind = iota
	// denyKindConcurrent is the in-flight layer: requests at the same time.
	// Wired by the concurrency limiter; the message vocabulary lands here so
	// both layers speak with one voice rather than inventing a second format.
	denyKindConcurrent
)

// denyScope is who owns the limit that fired.
type denyScope int

const (
	// scopePersonal -- the caller's own bucket. They can fix this themselves.
	scopePersonal denyScope = iota
	// scopeDatasource -- a backend's quota, shared by everyone aimed at it.
	// Naming the datasource matters: with per-instance quotas, "a datasource"
	// is not enough to know which dashboard to stop opening.
	scopeDatasource
	// scopeBlocked -- mode=blocked. No amount of waiting helps, and this is
	// also the default for anonymous traffic, so it must not read like a
	// transient failure.
	scopeBlocked
)

// denyMessageInput is everything the sentence needs. Passed as a struct because
// five positional arguments at a call site inside a long middleware is exactly
// where a silent argument swap hides.
type denyMessageInput struct {
	Scope denyScope
	Kind  denyKind
	// Limit is the configured ceiling: tokens/sec for QPS, slots for
	// concurrency. Zero or negative is treated as unknown and omitted rather
	// than printed as "(0)", which would read as "your limit is zero".
	Limit int
	// Target is the datasource UID, for scopeDatasource only.
	Target string
	// RetryAfter is the wait already computed for the Retry-After header; the
	// body and the header must agree, so both come from one value.
	RetryAfter time.Duration
	// Permanent marks a request that costs more than burst: it is refused on
	// every attempt regardless of waiting (rate.go:371 gates on n <= burst).
	// Telling this caller to "try again in 2 seconds" sends them into a retry
	// loop that cannot terminate, so the advice has to change, not just the
	// wording.
	Permanent bool
	// Cost/Burst quantify the permanent case -- "35 > 20" is what turns
	// "make the request smaller" into a known target.
	Cost  int
	Burst int
}

// String renders the user-facing sentence.
func (in denyMessageInput) String() string {
	if in.Scope == scopeBlocked {
		return "Datasource queries are not allowed for this account. " +
			"Contact your Grafana admin."
	}

	var who string
	switch in.Scope {
	case scopeDatasource:
		// Deliberately "This datasource" rather than the UID, even when the UID
		// is known.
		//
		// Only the UID is available here: resolving it to a display name means a
		// datasource cache lookup that misses on first use and falls through to
		// SQL (datasources/service/cache.go:91), and this limiter matters most
		// during a surge -- precisely when it must not add DB load. That trade
		// is settled (see datasourceTargets), so the question is only what to
		// show the reader.
		//
		// A raw UID is noise to them: seen live, the sentence read "Datasource
		// c95b31b5-7d94-4c40-943a-e5f1d51c8cfd query rate limit reached", where
		// 36 characters of hex crowd out the part that matters and identify
		// nothing a user can act on. A datasource quota is shared and
		// admin-owned, so their next step is the same regardless of which
		// datasource it was.
		//
		// The UID stays in the `datasource` body field for whoever is debugging,
		// and in the deny log for the operator, who can resolve it.
		// Possessive, so it reads as a sentence: "This datasource's query rate
		// limit reached", parallel with "Your personal query rate limit reached".
		who = "This datasource's"
	default:
		who = "Your personal"
	}

	// Waiting does not clear a concurrency rejection the way it clears a rate
	// one: the slots are held by the caller's own queries, so time passes and
	// nothing frees up until one of those returns. "Try again in N seconds"
	// would send them into a retry loop on a timer that has no bearing on when
	// capacity appears, so the advice has to name the action that does work.
	//
	// "Wait for your running queries to finish" rather than anything about
	// panels or tabs. Those exist only for a browser, and the identities most
	// likely to saturate this limit are service accounts and scripts, which
	// have neither -- telling an automated caller to close a tab is advice it
	// cannot act on. Every caller does have running queries, so that is the
	// one remedy true for all of them.
	if in.Kind == denyKindConcurrent {
		limitPart := ""
		if in.Limit > 0 {
			limitPart = fmt.Sprintf(" (%d %s)", in.Limit, in.unit())
		}
		return fmt.Sprintf("%s %s limit reached%s. ", who, in.kindNoun(), limitPart) +
			"Wait for your running queries to finish."
	}

	// A request over burst can never be admitted, so it gets advice that can
	// actually succeed -- fewer queries per request -- instead of a wait.
	if in.Permanent {
		return fmt.Sprintf(
			"%s %s limit is too small for this request (needs %d, limit is %d). "+
				"Split the dashboard into fewer panels, or ask your Grafana admin to raise the limit.",
			who, in.kindNoun(), in.Cost, in.Burst,
		)
	}

	limitPart := ""
	if in.Limit > 0 {
		limitPart = fmt.Sprintf(" (%d %s)", in.Limit, in.unit())
	}

	// Seconds, ceiled with a 1s floor, to match the Retry-After header exactly.
	secs := int(in.RetryAfter.Seconds())
	if in.RetryAfter > time.Duration(secs)*time.Second {
		secs++
	}
	if secs < 1 {
		secs = 1
	}

	suffix := "Please try again in %d second."
	if secs != 1 {
		suffix = "Please try again in %d seconds."
	}

	return fmt.Sprintf("%s %s limit reached%s. ", who, in.kindNoun(), limitPart) +
		fmt.Sprintf(suffix, secs)
}

// kindNoun names the limit in the words a user would use, not the internal ones.
func (in denyMessageInput) kindNoun() string {
	if in.Kind == denyKindConcurrent {
		return "concurrent request"
	}
	return "query rate"
}

// unit spells out what the number counts. Without it "(20)" is ambiguous
// between per-second and at-once -- the two things the reader must not confuse,
// since they call for opposite remedies.
func (in denyMessageInput) unit() string {
	if in.Kind == denyKindConcurrent {
		return "at a time"
	}
	return "queries/sec"
}

// scopeLabel and kindLabel are the machine-readable twins of the prose. A
// client (or our own e2e script) that needs to branch on "was this mine or the
// datasource's" should read these, not grep the sentence -- otherwise the
// wording is frozen by its own consumers.
func (in denyMessageInput) scopeLabel() string {
	switch in.Scope {
	case scopeDatasource:
		return "datasource"
	case scopeBlocked:
		return "blocked"
	default:
		return "personal"
	}
}

func (in denyMessageInput) kindLabel() string {
	if in.Kind == denyKindConcurrent {
		return "concurrent"
	}
	return "qps"
}
