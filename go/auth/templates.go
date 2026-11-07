package auth

// Port of packages/auth/src/templates.ts: the built-in subjects, plain-text and HTML bodies of every message Better
// IAM queues. The rendered text is identical to the TypeScript output for the same payload.

import (
	"math"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// RenderedMessage is a message ready for an email or SMS provider. HTML is only meaningful for email.
type RenderedMessage struct {
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html"`
}

// InvitationLinkInput is what TemplateLinks.Invitation receives.
type InvitationLinkInput struct {
	Kind      string // owner or member
	TenantID  string
	Token     string
	SignInURL string
}

// TokenLinkInput is what the token-carrying link builders receive.
type TokenLinkInput struct {
	TenantID  string
	Token     string
	SignInURL string
}

// MagicLinkInput is what TemplateLinks.MagicLink receives.
type MagicLinkInput struct {
	TenantID    string
	Token       string
	Destination string
	SignInURL   string
}

// TenantLinkInput is what TemplateLinks.Account receives.
type TenantLinkInput struct {
	TenantID  string
	SignInURL string
}

// CertificationLinkInput is what TemplateLinks.Certification receives.
type CertificationLinkInput struct {
	TenantID   string
	CampaignID string
	SignInURL  string
}

// DelegationLinkInput is what TemplateLinks.Delegation receives.
type DelegationLinkInput struct {
	TenantID     string
	DelegationID string
	SignInURL    string
}

// TeamLinkInput is what TemplateLinks.Team receives.
type TeamLinkInput struct {
	TenantID  string
	TeamID    string
	SignInURL string
}

// BillingLinkInput is what TemplateLinks.Billing receives (StatementID only for statements and reminders).
type BillingLinkInput struct {
	TenantID    string
	StatementID string
	SignInURL   string
}

// PrivacyLinkInput is what TemplateLinks.Privacy receives: with Token, the page that confirms a public data-subject
// request; with Handler, a request's page for whoever handles it; otherwise the person's own privacy page.
type PrivacyLinkInput struct {
	TenantID  string
	RequestID string
	Token     string
	// HasToken is true when the token was given (it may be empty).
	HasToken  bool
	Handler   bool
	SignInURL string
}

// ThreatsLinkInput is what TemplateLinks.Threats receives.
type ThreatsLinkInput struct {
	TenantID   string
	IncidentID string
	SignInURL  string
}

// GuestsLinkInput is what TemplateLinks.Guests receives.
type GuestsLinkInput struct {
	TenantID  string
	GuestID   string
	SignInURL string
}

// ClearancesLinkInput is what TemplateLinks.Clearances receives.
type ClearancesLinkInput struct {
	TenantID   string
	IdentityID string
	SignInURL  string
}

// TemplateLinks builds the links your application serves for token-carrying templates; a missing builder falls
// back to the raw token (or the account page). SignInURL is the organization's own sign-in address when the
// deployment has organization addresses or regions.
type TemplateLinks struct {
	Invitation      func(InvitationLinkInput) string
	PasswordReset   func(TokenLinkInput) string
	VerifyEmail     func(TokenLinkInput) string
	EmailChange     func(TokenLinkInput) string
	MagicLink       func(MagicLinkInput) string
	Account         func(TenantLinkInput) string
	Certification   func(CertificationLinkInput) string
	Delegation      func(DelegationLinkInput) string
	Team            func(TeamLinkInput) string
	Billing         func(BillingLinkInput) string
	Privacy         func(PrivacyLinkInput) string
	Threats         func(ThreatsLinkInput) string
	GuestInvitation func(TokenLinkInput) string
	Guests          func(GuestsLinkInput) string
	Clearances      func(ClearancesLinkInput) string
}

// TemplateOptions configures RenderDeliveryMessage.
type TemplateOptions struct {
	// AppName is the product name used in subjects and greetings (default "Better IAM").
	AppName *string
	Links   *TemplateLinks
}

// TemplateMessage is the part of a delivery the templates read.
type TemplateMessage struct {
	Template  string
	To        string
	Payload   map[string]string
	TenantID  string
	SignInURL string
}

func escapeHTML(value string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(value)
}

// oneLine turns control characters and line separators (which could break a mail header) into spaces.
func oneLine(value string) string {
	return core.JSTrim(replaceControls(value))
}

var browserTokens = [][2]string{
	{"Edg/", "Edge"},
	{"OPR/", "Opera"},
	{"SamsungBrowser/", "Samsung Internet"},
	{"Firefox/", "Firefox"},
	{"FxiOS/", "Firefox"},
	{"CriOS/", "Chrome"},
	{"Chrome/", "Chrome"},
	{"Safari/", "Safari"},
}

var systemTokens = [][2]string{
	{"Windows", "Windows"},
	{"iPhone", "iOS"},
	{"iPad", "iPadOS"},
	{"Android", "Android"},
	{"CrOS", "ChromeOS"},
	{"Macintosh", "macOS"},
	{"Mac OS X", "macOS"},
	{"Linux", "Linux"},
}

// DescribeUserAgent is a short description of a User-Agent for security notices ("Chrome on Windows"); "" for an
// empty one. The header is chosen by whoever sent the request, so it never reaches a message verbatim.
func DescribeUserAgent(userAgent string) string {
	if userAgent == "" {
		return ""
	}
	find := func(table [][2]string) string {
		for _, entry := range table {
			if strings.Contains(userAgent, entry[0]) {
				return entry[1]
			}
		}
		return ""
	}
	browser, system := find(browserTokens), find(systemTokens)
	switch {
	case browser != "" && system != "":
		return browser + " on " + system
	case browser != "":
		return browser
	case system != "":
		return "a browser or app on " + system
	}
	return "an unrecognized browser or app"
}

type templateAction struct {
	href          string
	label         string
	fallbackToken string
}

func layout(appName, title string, paragraphs []string, action *templateAction) string {
	var body strings.Builder
	for _, paragraph := range paragraphs {
		body.WriteString(`<p style="margin:0 0 16px">` + paragraph + `</p>`)
	}
	button := ""
	if action != nil {
		button = `<p style="margin:0 0 24px"><a href="` + escapeHTML(action.href) + `" style="display:inline-block;padding:10px 18px;background:#1d4ed8;color:#ffffff;border-radius:6px;text-decoration:none;font-weight:600">` + escapeHTML(action.label) + `</a></p><p style="margin:0 0 16px;font-size:13px;color:#555">Or paste this address into your browser:<br><span style="word-break:break-all">` + escapeHTML(action.href) + `</span></p>`
	}
	return `<!doctype html><html><body style="margin:0;padding:24px;background:#f5f6f8;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111"><div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:10px;padding:32px"><h1 style="font-size:20px;margin:0 0 20px">` + escapeHTML(title) + `</h1>` + body.String() + button + `<p style="margin:24px 0 0;font-size:12px;color:#777">` + escapeHTML(appName) + `</p></div></body></html>`
}

// numberOr is `Number(value) || fallback` (NaN and 0 take the fallback).
func numberOr(value string, present bool, fallback float64) float64 {
	if !present {
		return fallback
	}
	n := jsNumber(value)
	if n == 0 || math.IsNaN(n) {
		return fallback
	}
	return n
}

func plural(n float64, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// upperFirst is `value.charAt(0).toUpperCase() + value.slice(1)` for the first UTF-16 unit.
func upperFirst(value string) string {
	units := core.ToUTF16(value)
	if len(units) == 0 {
		return ""
	}
	if units[0] >= 0xD800 && units[0] <= 0xDFFF {
		// A surrogate has no case: the string comes back as it was.
		return value
	}
	return jsUpper(core.FromUTF16(units[:1])) + core.FromUTF16(units[1:])
}

// validDate parses `new Date(value)`: ok when the result is a valid date.
func validDate(value string, present bool) (float64, bool) {
	if !present {
		return 0, false
	}
	ms := parseDate(value)
	return ms, dateValid(ms)
}

// RenderDeliveryMessage renders the messages Better IAM queues (verify-email, password-reset, email-change,
// magic-link, code, mfa-code, new-sign-in, sign-in-failures, certification-review, certification-reminder,
// delegation-request, delegation-confirmation, team-join-request, team-join-decided, team-review-requested,
// spend-alert, spend-anomaly, billing-statement, payment-reminder, privacy-request-verify, privacy-request-received,
// privacy-request-update, privacy-request-due, workflow-message, threat-alert, license-waiting, license-activated,
// guest-invitation, guest-review, guest-sponsor-missing, clearance-reminder, clearance-status, owner-invitation,
// member-invitation) into a subject, plain text and HTML. It returns nil for templates it does not know (plugins,
// newer features), which the callback should render itself. The error is the TypeError the TypeScript renderer
// throws for a spend-anomaly item list holding null.
func RenderDeliveryMessage(message TemplateMessage, options TemplateOptions) (*RenderedMessage, error) {
	appName := "Better IAM"
	if options.AppName != nil {
		appName = *options.AppName
	}
	links := TemplateLinks{}
	if options.Links != nil {
		links = *options.Links
	}
	payload := message.Payload
	if payload == nil {
		payload = map[string]string{}
	}
	get := func(key string) (string, bool) {
		value, ok := payload[key]
		return value, ok
	}
	or := func(key, fallback string) string {
		if value, ok := payload[key]; ok {
			return value
		}
		return fallback
	}
	// truthy payload value
	has := func(key string) bool { return payload[key] != "" }
	linkTenant := or("tenantId", message.TenantID)
	site := message.SignInURL
	// the tenant the per-feature links use: message.tenantId ?? payload.tenantId
	featureTenant := message.TenantID
	if featureTenant == "" {
		featureTenant = payload["tenantId"]
	}
	account := func(tenantID string) string {
		if links.Account == nil {
			return ""
		}
		return links.Account(TenantLinkInput{TenantID: tenantID, SignInURL: site})
	}
	var accountAction *templateAction
	if message.TenantID != "" {
		accountAction = &templateAction{href: account(message.TenantID), label: "Review your account"}
	}
	tokenLine := func(token string) string {
		if token != "" {
			return "Code: " + token
		}
		return ""
	}
	compose := func(subject, title string, lines []string, action *templateAction) (*RenderedMessage, error) {
		textLines := append([]string(nil), lines...)
		htmlParagraphs := make([]string, len(lines))
		for index, line := range lines {
			htmlParagraphs[index] = escapeHTML(line)
		}
		var button *templateAction
		if action != nil && action.href != "" {
			textLines = append(textLines, action.label+": "+action.href)
			button = &templateAction{href: action.href, label: action.label}
		} else if action != nil && action.fallbackToken != "" {
			textLines = append(textLines, tokenLine(action.fallbackToken))
			htmlParagraphs = append(htmlParagraphs, "<code>"+escapeHTML(action.fallbackToken)+"</code>")
		}
		textLines = append(textLines, "", appName)
		return &RenderedMessage{
			// Subjects interpolate names and other stored values; a line break there would inject mail headers.
			Subject: oneLine(subject),
			Text:    strings.Join(textLines, "\n"),
			HTML:    layout(appName, title, htmlParagraphs, button),
		}, nil
	}
	expiry := func(minutes string) string { return "This link expires in " + minutes + " minutes." }
	tokenLink := func(builder func(TokenLinkInput) string) string {
		if builder == nil {
			return ""
		}
		return builder(TokenLinkInput{TenantID: linkTenant, Token: or("token", ""), SignInURL: site})
	}
	token, _ := get("token")
	switch message.Template {
	case "verify-email":
		return compose("Verify your email for "+appName, "Verify your email",
			[]string{"Confirm that this address belongs to you.", "This link is valid for 24 hours."},
			&templateAction{href: tokenLink(links.VerifyEmail), label: "Verify email", fallbackToken: token})
	case "password-reset":
		return compose("Reset your "+appName+" password", "Reset your password",
			[]string{"Someone asked to reset the password for this address. If it was not you, ignore this message.", expiry("10")},
			&templateAction{href: tokenLink(links.PasswordReset), label: "Choose a new password", fallbackToken: token})
	case "email-change":
		return compose("Confirm your new "+appName+" email", "Confirm your new email address",
			[]string{"Confirm that you want to sign in with this address from now on.", expiry("10")},
			&templateAction{href: tokenLink(links.EmailChange), label: "Confirm address", fallbackToken: token})
	case "magic-link":
		href := ""
		if links.MagicLink != nil {
			href = links.MagicLink(MagicLinkInput{TenantID: linkTenant, Token: or("token", ""), Destination: message.To, SignInURL: site})
		}
		return compose("Sign in to "+appName, "Your sign-in link",
			[]string{"Use the link below to sign in. Anyone with it can sign in as you, so do not forward it.", expiry("5")},
			&templateAction{href: href, label: "Sign in", fallbackToken: token})
	case "code":
		return compose("Your "+appName+" sign-in code", "Your sign-in code", []string{
			"Enter this code to sign in: " + or("token", ""),
			"It expires in 5 minutes. If you did not request it, ignore this message.",
		}, nil)
	case "mfa-code":
		return compose("Your "+appName+" verification code", "Your verification code", []string{
			"Enter this code to finish signing in: " + or("code", ""),
			"It expires in a few minutes. If you did not request it, change your password.",
		}, nil)
	case "new-sign-in":
		var where []string
		if has("label") {
			if label := sliceUTF16(oneLine(payload["label"]), 0, 80); label != "" {
				where = append(where, label)
			}
		}
		if described := DescribeUserAgent(payload["userAgent"]); described != "" {
			where = append(where, described)
		}
		if has("ip") {
			where = append(where, payload["ip"])
		}
		place := ""
		if len(where) > 0 {
			place = ": " + strings.Join(where, " · ")
		}
		return compose("New sign-in to "+appName, "New sign-in to your account", []string{
			"Your account was just used to sign in from a device we had not seen before" + place + ".",
			"Method: " + or("method", "unknown") + ". Time: " + or("time", "unknown") + ".",
			"If this was you, no action is needed. If not, change your password and sign out of every device.",
		}, accountAction)
	case "sign-in-failures":
		var where []string
		if described := DescribeUserAgent(payload["userAgent"]); described != "" {
			where = append(where, described)
		}
		if has("ip") {
			where = append(where, payload["ip"])
		}
		latest := ""
		if len(where) > 0 {
			latest = ", the latest from " + strings.Join(where, " · ")
		}
		return compose("Failed sign-in attempts on your "+appName+" account", "Failed sign-in attempts", []string{
			or("attempts", "Several") + " attempts to sign in to your account have failed since your last sign-in" + latest + ".",
			"Time of the latest attempt: " + or("time", "unknown") + ".",
			"Nobody has got in: your password held. If this was not you, change your password anywhere else it is used, and review the security activity on your account page.",
		}, accountAction)
	case "certification-review", "certification-reminder":
		reminder := message.Template == "certification-reminder"
		campaign := or("campaignName", "An access review")
		countKey := "items"
		if reminder {
			countKey = "pending"
		}
		countValue, countPresent := get(countKey)
		count := numberOr(countValue, countPresent, 0)
		due := ""
		if has("dueAt") {
			due = " Please decide by " + payload["dueAt"] + "."
		}
		href := ""
		if featureTenant != "" && has("campaignId") && links.Certification != nil {
			href = links.Certification(CertificationLinkInput{TenantID: featureTenant, CampaignID: payload["campaignId"], SignInURL: site})
		} else if featureTenant != "" {
			href = account(featureTenant)
		}
		subject, title := "Review access: "+campaign, "You have access to review"
		first := "You were asked to review " + core.NumberString(count) + " access " + plural(count, "item", "items") + " in " + campaign +
			": keep what people still need and revoke the rest." + due
		if reminder {
			subject, title = "Reminder: "+campaign+" is waiting for you", "Access review reminder"
			first = core.NumberString(count) + " access " + plural(count, "item still needs", "items still need") + " your decision in " + campaign + "." + due
		}
		return compose(subject, title, []string{first, "Undecided items may be kept or revoked automatically when the review closes."},
			&templateAction{href: href, label: "Review access"})
	case "delegation-request":
		agent := or("agentName", "An AI agent")
		daysValue, daysPresent := get("days")
		days := numberOr(daysValue, daysPresent, 0)
		href := delegationHref(links, featureTenant, payload, site, account)
		model := ""
		if has("model") {
			model = " (" + payload["model"] + ")"
		}
		period := ""
		if days != 0 {
			period = " for " + core.NumberString(days) + " " + plural(days, "day", "days")
		}
		lines := []string{
			agent + model + " asks for permission to act on your behalf" + period + ".",
			"It asks for: " + or("scopes", "a custom set of permissions") + ". It can never do more than you can yourself.",
		}
		if has("reason") {
			lines = append(lines, "Its reason: “"+payload["reason"]+"”")
		}
		lines = append(lines, "If you do not recognize this agent, deny the request. You can revoke a delegation at any time.")
		return compose(agent+" asks to act on your behalf", "An agent asks to act for you", lines,
			&templateAction{href: href, label: "Review the request"})
	case "team-review-requested":
		team := or("teamName", "your team")
		href := teamHref(links, featureTenant, payload, site, account)
		members := ""
		if has("memberCount") {
			members = " (" + payload["memberCount"] + " people)"
		}
		lines := []string{
			"An administrator asked the maintainers of " + team + " to confirm who still belongs" + members +
				": keep the people who still need the team's access, and remove the rest.",
		}
		if due, ok := validDate(payload["dueAt"], has("dueAt")); ok {
			outcome := "People nobody decides on then stay in the team."
			if payload["onUndecided"] == "remove" {
				outcome = "People nobody decides on then leave the team."
			}
			lines = append(lines, "Please decide by "+utcString(due)+". "+outcome)
		}
		if has("note") {
			lines = append(lines, "Note: “"+payload["note"]+"”")
		}
		return compose("Review the members of "+team, "Who still belongs in "+team+"?", lines,
			&templateAction{href: href, label: "Review the members"})
	case "team-join-request", "team-join-decided":
		team := or("teamName", "a team")
		href := teamHref(links, featureTenant, payload, site, account)
		if message.Template == "team-join-request" {
			who := or("requesterName", "Someone")
			email := ""
			if has("requesterEmail") {
				email = " (" + payload["requesterEmail"] + ")"
			}
			lines := []string{who + email + " asks to join " + team + ". Joining gives them the access the team holds."}
			if has("justification") {
				lines = append(lines, "Their reason: “"+payload["justification"]+"”")
			}
			lines = append(lines, "As a maintainer of the team you can approve or deny the request.")
			return compose(who+" asks to join "+team, "A request to join "+team, lines,
				&templateAction{href: href, label: "Review the request"})
		}
		approved := payload["decision"] == "approved"
		subject, title, first, label := "Your request to join "+team+" was declined", "Join request declined",
			"Your request to join "+team+" was declined.", "Review your account"
		if approved {
			subject, title, first, label = "You joined "+team, "Welcome to "+team,
				"Your request to join "+team+" was approved. You now have the access the team holds.", "Open the team"
		}
		lines := []string{first}
		if has("note") {
			lines = append(lines, "Note from the maintainer: “"+payload["note"]+"”")
		}
		return compose(subject, title, lines, &templateAction{href: href, label: label})
	case "delegation-confirmation":
		agent := or("agentName", "An AI agent")
		href := delegationHref(links, featureTenant, payload, site, account)
		lines := []string{
			agent + " is acting for you and wants to perform " + or("action", "an action") + " on " + or("resource", "a resource") +
				". You asked to confirm actions like this one before it takes them.",
		}
		if has("reason") {
			lines = append(lines, "Its reason: “"+payload["reason"]+"”")
		}
		lines = append(lines, "The request expires in "+or("minutes", "30")+" minutes. If you do not expect it, reject it and review the agent's access.")
		return compose(agent+" asks you to confirm an action", "Confirm an action by your agent", lines,
			&templateAction{href: href, label: "Review the request"})
	case "spend-alert", "spend-anomaly", "billing-statement", "payment-reminder":
		statement := message.Template == "billing-statement" || message.Template == "payment-reminder"
		href := ""
		if featureTenant != "" {
			if links.Billing != nil {
				input := BillingLinkInput{TenantID: featureTenant, SignInURL: site}
				if statement && has("statementId") {
					input.StatementID = payload["statementId"]
				}
				href = links.Billing(input)
			} else {
				href = account(featureTenant)
			}
		}
		switch message.Template {
		case "spend-anomaly":
			var items []any
			if parsed, err := core.ParseJSONString(or("items", "[]")); err == nil {
				if list, ok := parsed.([]any); ok {
					items = list
				}
			}
			countValue, countPresent := get("count")
			count := numberOr(countValue, countPresent, float64(len(items)))
			day := or("day", "yesterday")
			lines := []string{
				core.NumberString(count) + " " + plural(count, "person, team or meter", "people, teams or meters") + " spent far more than usual on " + day + ":",
			}
			for _, item := range items {
				if item == nil || core.IsUndefined(item) {
					return nil, &core.TypeError{Message: "Cannot read properties of " + jsString(item) + " (reading 'what')"}
				}
				field := func(key string) string {
					object, ok := item.(*core.Object)
					if !ok {
						return ""
					}
					value := object.Get(key)
					if value == nil || core.IsUndefined(value) {
						return ""
					}
					return jsString(value)
				}
				lines = append(lines, field("what")+": "+field("spent")+" (usually "+field("usual")+" a day)")
			}
			lines = append(lines, "If this was not expected, find out who or what is behind it before it adds up.")
			return compose("Unusual spend at "+or("tenantName", "your organization")+" on "+day, "Unusual spend", lines,
				&templateAction{href: href, label: "Review spend"})
		case "payment-reminder":
			overdue := payload["overdue"] == "true"
			daysValue, daysPresent := get("days")
			days := math.Abs(numberOr(daysValue, daysPresent, 0))
			number := or("number", "your invoice")
			daySuffix := "s"
			if days == 1 {
				daySuffix = ""
			}
			subject := "Invoice " + number + " is due today"
			if overdue {
				subject = "Invoice " + number + " is " + core.NumberString(days) + " day" + daySuffix + " overdue"
			} else if days != 0 {
				subject = "Invoice " + number + " is due in " + core.NumberString(days) + " day" + daySuffix
			}
			title := "Payment reminder"
			closing := "If you have already paid it, you can ignore this reminder."
			if overdue {
				title = "Payment overdue"
				closing = "Please pay it as soon as you can, or reply if you believe it is wrong."
			}
			first := strings.Replace(or("amountDue", "An amount")+" is still due on invoice "+number+" for "+or("tenantName", "your organization")+
				" ("+or("period", "")+"), due "+or("dueAt", "")+".", " ()", "", 1)
			return compose(subject, title, []string{first, closing}, &templateAction{href: href, label: "View invoice"})
		}
		if statement {
			organization := or("tenantName", "your organization")
			subscription := payload["reason"] == "subscription"
			subject := collapseWhitespace("Your " + appName + " statement " + or("number", "") + " for " + or("period", "last month"))
			first := "The statement for " + organization + " for " + or("period", "last month") + " is ready: " + or("total", "see the statement") +
				" due by " + or("dueAt", "the due date") + "."
			if subscription {
				first = "The first invoice of the new subscription for " + organization + " is ready: " + or("total", "see the invoice") +
					" due by " + or("dueAt", "the due date") + "."
			}
			return compose(subject, core.JSTrim("Statement "+or("number", "")), []string{
				first,
				"Subtotal " + or("subtotal", "") + ", credits applied " + or("credits", "0") + ".",
			}, &templateAction{href: href, label: "View statement"})
		}
		budget := or("budgetName", "A budget")
		subject := or("subjectName", "The budget’s subject")
		window := ""
		if has("windowStart") && has("windowEnd") && payload["windowStart"] != payload["windowEnd"] {
			window = " (" + payload["windowStart"] + " to " + payload["windowEnd"] + ")"
		} else if has("windowStart") {
			window = " (" + payload["windowStart"] + ")"
		}
		forecast := payload["kind"] == "forecast"
		mailSubject := budget + " has reached " + or("threshold", "100") + "% of its budget"
		title := "Spend alert"
		first := subject + " has spent " + or("spent", "") + " of the " + or("amount", "") + " budget “" + budget + "”" + window + ": " +
			or("percent", or("threshold", "")) + "%."
		if forecast {
			mailSubject = budget + " is on track to exceed its budget"
			title = "Spend forecast alert"
			first = "At the current pace " + subject + " will spend about " + or("forecast", "more than planned") + " against the " +
				or("amount", "") + " budget “" + budget + "”" + window + "."
		}
		lines := []string{first}
		if !forecast && has("forecast") {
			lines = append(lines, "Projected by the end of the period: "+payload["forecast"]+".")
		}
		lines = append(lines, "Review spend by person, team and meter to see what drives it.")
		return compose(mailSubject, title, lines, &templateAction{href: href, label: "Review spend"})
	case "privacy-request-verify", "privacy-request-received", "privacy-request-update", "privacy-request-due":
		organization := or("tenantName", "the organization")
		number := or("number", "your request")
		kinds := map[string]string{
			"access":        "a copy of personal data",
			"portability":   "personal data in a portable format",
			"erasure":       "erasure of personal data",
			"rectification": "correction of personal data",
			"restriction":   "restriction of processing",
			"objection":     "an objection to processing",
			"opt-out":       "an opt-out of sale or sharing",
		}
		asked, ok := kinds[or("type", "")]
		if !ok {
			asked = "a privacy request"
		}
		dueText := ""
		if has("dueAt") {
			if due := jsNumber(payload["dueAt"]); dateValid(due) {
				dueText = utcString(due)
			}
		}
		link := func(input PrivacyLinkInput) string {
			if featureTenant == "" {
				return ""
			}
			if links.Privacy != nil {
				input.TenantID = featureTenant
				if has("requestId") {
					input.RequestID = payload["requestId"]
				}
				input.SignInURL = site
				return links.Privacy(input)
			}
			if input.HasToken && input.Token != "" {
				return ""
			}
			return account(featureTenant)
		}
		switch message.Template {
		case "privacy-request-verify":
			lines := []string{
				"We received a request for " + asked + " from this address (reference " + number + "). Confirm it so " + organization + " can start handling it.",
				"If you did not make this request, ignore this email: nothing happens until it is confirmed, and it lapses after seven days.",
			}
			if has("requestId") && links.Privacy == nil {
				lines = append(lines, "Request ID: "+payload["requestId"])
			}
			return compose("Confirm your privacy request to "+organization, "Confirm your request", lines,
				&templateAction{href: link(PrivacyLinkInput{Token: or("token", ""), HasToken: true}), label: "Confirm request", fallbackToken: token})
		case "privacy-request-received":
			regulation, channel := "", ""
			if has("regulation") {
				regulation = ", " + jsUpper(payload["regulation"])
			}
			if has("channel") {
				channel = ", via " + payload["channel"]
			}
			lines := []string{organization + " received a request for " + asked + " (" + number + regulation + channel + ")."}
			if dueText != "" {
				lines = append(lines, "It must be answered by "+dueText+".")
			}
			return compose("New privacy request "+number+": "+asked, "A privacy request needs handling", lines,
				&templateAction{href: link(PrivacyLinkInput{Handler: true}), label: "Open the request"})
		case "privacy-request-due":
			overdue := payload["overdue"] == "true"
			subject, title := "Privacy request "+number+" is due soon", "Privacy request due soon"
			deadline := dueText
			if deadline == "" {
				deadline = "its deadline"
			}
			line := "The request for " + asked + " (" + number + ") at " + organization + " must be answered by " + deadline + "."
			if overdue {
				subject, title = "Privacy request "+number+" is overdue", "Privacy request overdue"
				on := ""
				if dueText != "" {
					on = " on " + dueText
				}
				line = "The request for " + asked + " (" + number + ") at " + organization + " passed its deadline" + on +
					". Answer it now, or extend it if the regulation allows and you have not yet."
			}
			return compose(subject, title, []string{line}, &templateAction{href: link(PrivacyLinkInput{Handler: true}), label: "Open the request"})
		}
		event := or("event", "completed")
		reasons := map[string]string{
			"unverified": "we could not confirm who made it",
			"unfounded":  "it is manifestly unfounded",
			"excessive":  "it is excessive or repetitive",
			"exempt":     "a legal exemption applies (for example a legal obligation to keep the data)",
			"duplicate":  "it repeats a request already being handled",
			"no-data":    "it holds no personal data about you",
			"other":      "of the reason given by the organization",
		}
		var lines []string
		subject, title := "Your privacy request "+number+" is complete", "Request complete"
		switch event {
		case "extended":
			subject, title = "More time needed for your privacy request "+number, "Request extended"
			lines = []string{organization + " needs more time to answer your request for " + asked + " (" + number + ")."}
			if dueText != "" {
				lines = append(lines, "You will receive an answer by "+dueText+".")
			}
		case "rejected":
			subject, title = "Your privacy request "+number+" was declined", "Request declined"
			reason, ok := reasons[or("reason", "other")]
			if !ok {
				reason = reasons["other"]
			}
			lines = []string{
				organization + " declined your request for " + asked + " (" + number + ") because " + reason + ".",
				"You may contact the organization’s privacy contact, or lodge a complaint with a data protection authority.",
			}
		default:
			lines = []string{organization + " completed your request for " + asked + " (" + number + ")."}
			if payload["exportReady"] == "true" {
				lines = append(lines, "Your data is ready to download for a limited time from your privacy page after signing in.")
			}
			if payload["type"] == "erasure" {
				lines = append(lines, "Your personal data has been erased; this is the last message about it.")
			}
		}
		var action *templateAction
		if !(payload["type"] == "erasure" && event == "completed") {
			action = &templateAction{href: link(PrivacyLinkInput{}), label: "View your privacy settings"}
		}
		return compose(subject, title, lines, action)
	case "threat-alert":
		href := ""
		if featureTenant != "" {
			if links.Threats != nil {
				input := ThreatsLinkInput{TenantID: featureTenant, SignInURL: site}
				if has("incidentId") {
					input.IncidentID = payload["incidentId"]
				}
				href = links.Threats(input)
			} else {
				href = account(featureTenant)
			}
		}
		organization := or("tenantName", "your organization")
		title := or("title", "Suspicious activity")
		severity := or("severity", "unknown")
		detectionsValue, detectionsPresent := get("detections")
		count := numberOr(detectionsValue, detectionsPresent, 1)
		involving := ""
		if has("subject") {
			involving = " involving " + payload["subject"]
		}
		lines := []string{title + involving + " at " + organization + "."}
		if has("summary") {
			lines = append(lines, payload["summary"])
		}
		lines = append(lines,
			"Severity: "+severity+". "+core.NumberString(count)+" "+plural(count, "detection", "detections")+" so far.",
			"If this activity was not expected, open the incident and respond: end the sessions, contain the account, or block the network.")
		return compose(upperFirst(severity)+" security incident at "+organization+": "+title, "Security incident", lines,
			&templateAction{href: href, label: "Review the incident"})
	case "workflow-message":
		// Written by an administrator in a lifecycle workflow: plain text, one paragraph per line.
		subject := sliceUTF16(or("subject", "A message from "+or("tenantName", appName)), 0, 300)
		body := or("body", "")
		lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
		if len(lines) > 200 {
			lines = lines[:200]
		}
		var action *templateAction
		if message.TenantID != "" {
			action = accountAction
		}
		return compose(subject, subject, lines, action)
	case "guest-invitation":
		tenantName := or("tenantName", "an organization")
		inviter, sponsor := payload["inviterName"], payload["sponsorName"]
		subjectLead, lead := "You are invited", "You have been invited"
		if inviter != "" {
			subjectLead, lead = inviter+" invited you", inviter+" invited"
		}
		sponsors := ""
		if sponsor != "" && sponsor != inviter {
			sponsors = " " + sponsor + " sponsors your access."
		}
		by := ""
		if expires, ok := validDate(payload["expiresAt"], has("expiresAt")); ok {
			by = " by " + utcString(expires)
		}
		lines := []string{lead + " you to collaborate with " + tenantName + " as a guest." + sponsors}
		if has("message") {
			lines = append(lines, "Their message: “"+payload["message"]+"”")
		}
		lines = append(lines, "Guest access is limited, and it ends unless your sponsor renews it.",
			"The invitation is personal: accept it from the same email address"+by+".")
		return compose(subjectLead+" to join "+tenantName+" as a guest", "Join "+tenantName+" as a guest", lines,
			&templateAction{href: tokenLink(links.GuestInvitation), label: "Accept invitation", fallbackToken: token})
	case "guest-review", "guest-sponsor-missing":
		href := ""
		if featureTenant != "" {
			if links.Guests != nil {
				input := GuestsLinkInput{TenantID: featureTenant, SignInURL: site}
				if has("guestId") {
					input.GuestID = payload["guestId"]
				}
				href = links.Guests(input)
			} else {
				href = account(featureTenant)
			}
		}
		organization := or("tenantName", "your organization")
		guest := or("guestName", "A guest")
		who := guest
		if has("guestEmail") {
			who += " (" + payload["guestEmail"] + ")"
		}
		if message.Template == "guest-sponsor-missing" {
			first := "The person who sponsored " + who + " is no longer an active member of " + organization + "."
			if has("sponsorName") {
				first = payload["sponsorName"] + ", who sponsored " + who + ", is no longer an active member of " + organization + "."
			}
			return compose(guest+" at "+organization+" has no sponsor", "A guest needs a sponsor", []string{
				first,
				"Assign the guest a new sponsor, or remove them if nobody vouches for them any more.",
			}, &templateAction{href: href, label: "Review the guest"})
		}
		ends, endsValid := validDate(payload["expiresAt"], has("expiresAt"))
		review, reviewValid := validDate(payload["reviewDueAt"], has("reviewDueAt"))
		lines := []string{"You sponsor " + who + ", a guest at " + organization + "."}
		if endsValid {
			lines = append(lines, "Their access ends on "+utcString(ends)+" unless you renew it.")
		}
		if reviewValid && (!endsValid || review < ends) {
			lines = append(lines, "Please confirm by "+utcString(review)+" that they still need it.")
		}
		lines = append(lines, "Renew their access if they still need it; otherwise let it end, or ask an administrator to remove them.")
		return compose("Does "+guest+" still need access to "+organization+"?", "Review a guest you sponsor", lines,
			&templateAction{href: href, label: "Review the guest"})
	case "owner-invitation", "member-invitation":
		kind := "member"
		if message.Template == "owner-invitation" {
			kind = "owner"
		}
		tenantName := or("tenantName", "an organization")
		lead := "You have been invited you to join " + tenantName + "."
		if has("inviterName") {
			lead = payload["inviterName"] + " invited you to join " + tenantName + "."
		}
		subject, title := "Join "+tenantName+" on "+appName, "Join "+tenantName
		if kind == "owner" {
			lead = "You have been invited to set up " + tenantName + " as its owner."
			subject, title = "Set up "+tenantName+" on "+appName, "Set up "+tenantName
		}
		href := ""
		if links.Invitation != nil {
			href = links.Invitation(InvitationLinkInput{Kind: kind, TenantID: linkTenant, Token: or("token", ""), SignInURL: site})
		}
		return compose(subject, title,
			[]string{lead, "The invitation is personal and expires; accept it from the same email address."},
			&templateAction{href: href, label: "Accept invitation", fallbackToken: token})
	case "license-waiting", "license-activated":
		product := or("productName", or("productKey", "a license"))
		organization := payload["tenantName"]
		if organization == "" {
			organization = "your organization"
		}
		if message.Template == "license-waiting" {
			return compose("You are on the waiting list for "+product, "Waiting for a "+product+" seat", []string{
				"You were given " + product + " at " + organization + ", but every seat is taken right now, so you are on the waiting list.",
				"You get the next free seat automatically, and we will let you know when it is yours.",
			}, accountAction)
		}
		return compose("Your "+product+" seat is ready", product+" is ready for you", []string{
			"A seat of " + product + " at " + organization + " became free and is now yours.",
			"You can use everything it includes right away.",
		}, accountAction)
	case "clearance-reminder", "clearance-status":
		// Security clearances. Mail passes through third-party providers, so these name the level only: never
		// compartments, caveats or the reasons officers recorded.
		organization := payload["tenantName"]
		if organization == "" {
			organization = "your organization"
		}
		level := ""
		if has("levelName") {
			level = " (level: " + payload["levelName"] + ")"
		}
		if message.Template == "clearance-reminder" {
			href := ""
			if featureTenant != "" {
				if links.Clearances != nil {
					input := ClearancesLinkInput{TenantID: featureTenant, SignInURL: site}
					if has("identityId") {
						input.IdentityID = payload["identityId"]
					}
					href = links.Clearances(input)
				} else {
					href = account(featureTenant)
				}
			}
			person := or("personName", "A person")
			interim := payload["status"] == "interim"
			article, prefix := "a", ""
			if interim {
				article, prefix = "an interim", "interim "
			}
			lines := []string{person + " holds " + article + " security clearance at " + organization + level + "."}
			if reinvestigation, ok := validDate(payload["reinvestigationDue"], has("reinvestigationDue")); ok {
				lines = append(lines, "Their periodic reinvestigation is due on "+utcString(reinvestigation)+".")
			}
			if ends, ok := validDate(payload["expiresAt"], has("expiresAt")); ok {
				lines = append(lines, "The "+prefix+"clearance ends on "+utcString(ends)+" unless it is renewed.")
			}
			lines = append(lines, "Review the clearance: schedule the investigation, renew or end it.")
			return compose("Clearance review due at "+organization, "Clearance review due", lines,
				&templateAction{href: href, label: "Review the clearance"})
		}
		status := payload["status"]
		outcome := "suspended"
		if status == "reinstated" {
			outcome = "reinstated"
		} else if status == "revoked" {
			outcome = "revoked"
		}
		closing := "Access to classified resources that depends on it has stopped. Your security officer can tell you more."
		if status == "reinstated" {
			closing = "Access that depends on it is available again."
		}
		return compose("Your security clearance at "+organization+" was "+outcome, "Clearance "+outcome, []string{
			"Your security clearance at " + organization + level + " was " + outcome + ".",
			closing,
		}, accountAction)
	}
	return nil, nil
}

func delegationHref(links TemplateLinks, tenantID string, payload map[string]string, site string, account func(string) string) string {
	if tenantID != "" && payload["delegationId"] != "" && links.Delegation != nil {
		return links.Delegation(DelegationLinkInput{TenantID: tenantID, DelegationID: payload["delegationId"], SignInURL: site})
	}
	if tenantID != "" {
		return account(tenantID)
	}
	return ""
}

func teamHref(links TemplateLinks, tenantID string, payload map[string]string, site string, account func(string) string) string {
	if tenantID != "" && payload["teamId"] != "" && links.Team != nil {
		return links.Team(TeamLinkInput{TenantID: tenantID, TeamID: payload["teamId"], SignInURL: site})
	}
	if tenantID != "" {
		return account(tenantID)
	}
	return ""
}

// collapseWhitespace is `value.replace(/\s+/g, ' ')`.
func collapseWhitespace(value string) string {
	var b strings.Builder
	inSpace := false
	for i := 0; i < len(value); {
		r, size := decodeWTF8(value, i)
		if jsSpace(r) {
			if !inSpace {
				b.WriteByte(' ')
			}
			inSpace = true
		} else {
			inSpace = false
			b.WriteString(value[i : i+size])
		}
		i += size
	}
	return b.String()
}
