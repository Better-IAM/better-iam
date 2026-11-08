package server

// Port of packages/server/src/billing-invoices.ts: invoicing helpers without storage: validation of invoice items,
// coupons and credit notes, and the printable invoice (HTML a browser can save as PDF, like a hosted invoice page).
// The transactional side lives in billing_service.go.

import (
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// signedAmountMicros is an amount in currency units that may be negative (a credit item), as micros.
func signedAmountMicros(value any, name string) (float64, error) {
	number, ok := billFinite(value)
	if !ok || math.Abs(number) > 1e9 {
		return 0, invalidInput(name + " must be an amount from -1000000000 to 1000000000")
	}
	return roundMicros(number * 1_000_000), nil
}

// InvoiceItemInput (billing-invoices.ts invoiceItemInput): Validated invoice item input: description, unit amount
// (currency units, negative for a credit), quantity, period. The result is {description, quantity,
// unitAmountMicros, amountMicros, period?, metadata?}.
func InvoiceItemInput(input *core.Object) (result *core.Object, err error) {
	description, err := Text(input.Get("description"), "description", 256)
	if err != nil {
		return nil, err
	}
	description = core.JSTrim(description)
	unitAmount, err := signedAmountMicros(input.Get("amount"), "amount")
	if err != nil {
		return nil, err
	}
	rawQuantity := input.Get("quantity")
	if isUndefined(rawQuantity) {
		rawQuantity = 1.0
	}
	quantity, ok := billFinite(rawQuantity)
	if !ok || quantity <= 0 || quantity > 1e9 {
		return nil, invalidInput("quantity must be a positive number")
	}
	period := ""
	if raw := input.Get("period"); !isUndefined(raw) {
		if period, err = BillingPeriod(raw, "period"); err != nil {
			return nil, err
		}
	}
	var metadata *core.Object
	if raw := input.Get("metadata"); !isUndefined(raw) {
		source, err := Object(raw)
		if err != nil {
			return nil, err
		}
		keys := source.Keys()
		if len(keys) > 20 {
			return nil, invalidInput("metadata may hold at most 20 entries")
		}
		metadata = core.NewObject()
		for _, key := range keys {
			name, err := Text(key, "metadata key", 64)
			if err != nil {
				return nil, err
			}
			value, err := Text(source.Get(key), "metadata."+key, 256)
			if err != nil {
				return nil, err
			}
			metadata.Set(name, value)
		}
	}
	result = core.NewObject("description", description, "quantity", quantity, "unitAmountMicros", unitAmount,
		"amountMicros", roundCents(unitAmount*quantity))
	if period != "" {
		result.Set("period", period)
	}
	if metadata != nil {
		result.Set("metadata", metadata)
	}
	return result, nil
}

var couponCodePattern = regexp.MustCompile(`^[A-Z0-9][A-Z0-9_-]{2,31}$`)

// jsUpperSpecial are String.prototype.toUpperCase's unconditional one-to-many mappings that end in ASCII letters
// (the only ones a coupon code can keep).
var jsUpperSpecial = map[rune]string{
	'ß': "SS", 'ﬀ': "FF", 'ﬁ': "FI", 'ﬂ': "FL", 'ﬃ': "FFI", 'ﬄ': "FFL", 'ﬅ': "ST", 'ﬆ': "ST",
}

// couponUpper is `value.toUpperCase()` for coupon codes.
func couponUpper(value string) string {
	var b strings.Builder
	for _, r := range value {
		if special, ok := jsUpperSpecial[r]; ok {
			b.WriteString(special)
			continue
		}
		b.WriteString(strings.ToUpper(string(r)))
	}
	return b.String()
}

// CouponCode (billing-invoices.ts couponCode): A coupon code: 3-32 letters, digits, `-` or `_` (stored in upper
// case).
func CouponCode(value any) (result string, err error) {
	code := ""
	if text, ok := value.(string); ok {
		code = couponUpper(core.JSTrim(text))
	}
	if !couponCodePattern.MatchString(code) {
		return "", invalidInput("code must be 3-32 letters, digits, - or _")
	}
	return code, nil
}

// CouponSettings (billing-invoices.ts couponSettings): Validated coupon settings: `percentOff` or `amountOff`, a
// duration, and redemption limits. The result is {code, name, duration, percentOff?, amountOffMicros?,
// durationInMonths?, maxRedemptions?, redeemBy?}.
func CouponSettings(input *core.Object, now int64) (result *core.Object, err error) {
	code, err := CouponCode(input.Get("code"))
	if err != nil {
		return nil, err
	}
	name := code
	if raw := input.Get("name"); !isUndefined(raw) {
		text, err := Text(raw, "name", 128)
		if err != nil {
			return nil, err
		}
		name = core.JSTrim(text)
	}
	hasPercent := !nullish(input.Get("percentOff"))
	hasAmount := !nullish(input.Get("amountOff"))
	if hasPercent == hasAmount {
		return nil, invalidInput("Give either percentOff or amountOff")
	}
	var percentOff any = core.Undefined
	if hasPercent {
		value, ok := billFinite(input.Get("percentOff"))
		if !ok || value <= 0 || value > 100 {
			return nil, invalidInput("percentOff must be above 0 and at most 100")
		}
		percentOff = jsMathRound(value*1000) / 1000
	}
	var amountOff any = core.Undefined
	if hasAmount {
		micros, err := signedAmountMicros(input.Get("amountOff"), "amountOff")
		if err != nil {
			return nil, err
		}
		if micros <= 0 {
			return nil, invalidInput("amountOff must be above 0")
		}
		amountOff = micros
	}
	duration := coalesce(input.Get("duration"), "once")
	if duration != "once" && duration != "repeating" && duration != "forever" {
		return nil, invalidInput("duration must be 'once', 'repeating' or 'forever'")
	}
	var durationInMonths any = core.Undefined
	if duration == "repeating" {
		months, err := Integer(input.Get("durationInMonths"), "durationInMonths", 1, 120)
		if err != nil {
			return nil, err
		}
		durationInMonths = months
	}
	if duration != "repeating" && !isUndefined(input.Get("durationInMonths")) {
		return nil, invalidInput("durationInMonths is only for repeating coupons")
	}
	var maxRedemptions any = core.Undefined
	if raw := input.Get("maxRedemptions"); !isUndefined(raw) {
		limit, err := Integer(raw, "maxRedemptions", 1, 1_000_000)
		if err != nil {
			return nil, err
		}
		maxRedemptions = limit
	}
	var redeemBy any = core.Undefined
	if raw := input.Get("redeemBy"); !isUndefined(raw) {
		at, err := Integer(raw, "redeemBy", float64(now)+1, maxSafeInteger)
		if err != nil {
			return nil, err
		}
		redeemBy = at
	}
	result = core.NewObject("code", code, "name", name, "duration", duration)
	for _, member := range []struct {
		key   string
		value any
	}{{"percentOff", percentOff}, {"amountOffMicros", amountOff}, {"durationInMonths", durationInMonths}, {"maxRedemptions", maxRedemptions}, {"redeemBy", redeemBy}} {
		if !isUndefined(member.value) {
			result.Set(member.key, member.value)
		}
	}
	return result, nil
}

var creditNoteReasons = []string{"duplicate", "fraudulent", "order_change", "product_unsatisfactory", "other"}

// CreditNoteReason (billing-invoices.ts creditNoteReason): A credit note reason (Stripe's list).
func CreditNoteReason(value any) (result string, err error) {
	reason := coalesce(value, "other")
	if text, ok := reason.(string); ok && slices.Contains(creditNoteReasons, text) {
		return text, nil
	}
	return "", invalidInput("reason must be one of " + strings.Join(creditNoteReasons, ", "))
}

var htmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")

func invoiceEscape(value string) string { return htmlEscaper.Replace(value) }

// currencySymbols are the en-US currency symbols Intl.NumberFormat prints that differ from `{CODE} ` (Node 24,
// ICU 78).
var currencySymbols = map[string]string{
	"AUD": "A$", "BRL": "R$", "CAD": "CA$", "CNY": "CN¥", "EUR": "€", "GBP": "£", "HKD": "HK$", "ILS": "₪",
	"INR": "₹", "JPY": "¥", "KRW": "₩", "MXN": "MX$", "NZD": "NZ$", "PHP": "₱", "TWD": "NT$", "USD": "$",
	"VND": "₫", "XAF": "FCFA ", "XCD": "EC$", "XCG": "Cg. ", "XOF": "F CFA ", "XPF": "CFPF ",
}

var wellFormedCurrency = regexp.MustCompile(`^[A-Za-z]{3}$`)

// roundDecimal rounds an unsigned decimal string ("123.4567") half up to `places` fraction digits and returns the
// integer and fraction digits (the fraction exactly `places` long).
func roundDecimal(text string, places int) (string, string) {
	whole, fraction, _ := strings.Cut(text, ".")
	for len(fraction) <= places {
		fraction += "0"
	}
	roundUp := fraction[places] >= '5'
	digits := []byte(whole + fraction[:places])
	if roundUp {
		index := len(digits) - 1
		for ; index >= 0; index-- {
			if digits[index] == '9' {
				digits[index] = '0'
				continue
			}
			digits[index]++
			break
		}
		if index < 0 {
			digits = append([]byte{'1'}, digits...)
		}
	}
	split := len(digits) - places
	return string(digits[:split]), string(digits[split:])
}

// groupThousands inserts en-US grouping separators into integer digits.
func groupThousands(digits string) string {
	if len(digits) <= 3 {
		return digits
	}
	var b strings.Builder
	head := len(digits) % 3
	if head > 0 {
		b.WriteString(digits[:head])
	}
	for index := head; index < len(digits); index += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(digits[index : index+3])
	}
	return b.String()
}

// localeNumber formats a number as Intl.NumberFormat('en-US') does with the given fraction digits (rounding the
// shortest decimal representation half away from zero, grouping thousands, keeping the sign of negative values that
// round to zero). It returns the sign and the digits separately.
func localeNumber(value float64, minimum, maximum int) (string, string) {
	sign := ""
	if value < 0 || (value == 0 && math.Signbit(value)) {
		sign = "-"
	}
	if math.IsNaN(value) {
		return "", "NaN"
	}
	if math.IsInf(value, 0) {
		return sign, "∞"
	}
	whole, fraction := roundDecimal(strconv.FormatFloat(math.Abs(value), 'f', -1, 64), maximum)
	for len(fraction) > minimum && strings.HasSuffix(fraction, "0") {
		fraction = fraction[:len(fraction)-1]
	}
	text := groupThousands(whole)
	if fraction != "" {
		text += "." + fraction
	}
	return sign, text
}

// jsToFixed is Number.prototype.toFixed.
func jsToFixed(value float64, digits int) string {
	if math.IsNaN(value) {
		return "NaN"
	}
	if math.Abs(value) >= 1e21 || math.IsInf(value, 0) {
		return core.NumberString(value)
	}
	sign := ""
	if value < 0 {
		sign = "-"
	}
	// The exact decimal expansion of the double, rounded with ties to the larger magnitude.
	whole, fraction := roundDecimal(strconv.FormatFloat(math.Abs(value), 'f', 1100, 64), digits)
	if strings.Trim(whole+fraction, "0") == "" {
		sign = ""
	}
	if digits == 0 {
		return sign + whole
	}
	return sign + whole + "." + fraction
}

// invoiceMoney is billing-invoices.ts formatter: money for invoices: cents, or six decimals for fractions of a cent
// (per-token and per-call prices).
func invoiceMoney(currency string) func(micros float64) string {
	return func(micros float64) string {
		digits := 2
		if micros != 0 && math.Abs(micros) < 10_000 {
			digits = 6
		}
		units := micros / 1_000_000
		if digits == 2 {
			units = unitsOf(micros)
		}
		if !wellFormedCurrency.MatchString(currency) {
			return currency + " " + jsToFixed(units, digits)
		}
		code := strings.ToUpper(currency)
		symbol, ok := currencySymbols[code]
		if !ok {
			symbol = code + " "
		}
		sign, text := localeNumber(units, digits, digits)
		return sign + symbol + text
	}
}

// invoiceDay is `new Date(at).toISOString().slice(0, 10)`.
func invoiceDay(at float64) string { return isoString(at)[:10] }

// quantityText is `value.toLocaleString('en-US', { maximumFractionDigits: 4 })`.
func quantityText(value float64) string {
	sign, text := localeNumber(value, 0, 4)
	return sign + text
}

func lineRows(line *core.Object, money func(float64) string) string {
	tiers := billObjects(line.Get("tiers"))
	unit := ""
	if billHas(line, "unitAmountMicros") {
		unit = money(billNumber(line, "unitAmountMicros"))
	} else if len(tiers) == 1 {
		unit = money(billNumber(tiers[0], "unitAmountMicros"))
	}
	details := []string{}
	if period, ok := line.Get("servicePeriod").(*core.Object); ok && period != nil {
		details = append(details, invoiceDay(billNumber(period, "start"))+" to "+invoiceDay(billNumber(period, "end")-1))
	}
	if billHas(line, "proration") {
		details = append(details, core.NumberString(jsMathRound(billNumber(line, "proration")*1000)/10)+"% of the month")
	}
	if truthy(line.Get("includedQuantity")) {
		details = append(details, quantityText(billNumber(line, "includedQuantity"))+" included")
	}
	if member(line.Get("price"), "source") == "plan" {
		details = append(details, "plan price")
	}
	if billHas(line, "adjustedFromMicros") {
		details = append(details, "adjusted from "+money(billNumber(line, "adjustedFromMicros")))
	}
	var b strings.Builder
	b.WriteString("<tr><td>")
	b.WriteString(invoiceEscape(jsString(line.Get("name"))))
	if len(details) > 0 {
		b.WriteString(`<div class="muted">` + invoiceEscape(strings.Join(details, " · ")) + "</div>")
	}
	b.WriteString(`</td><td class="num">` + invoiceEscape(quantityText(billNumber(line, "quantity"))) + " " + invoiceEscape(jsString(line.Get("unit"))))
	b.WriteString(`</td><td class="num">` + invoiceEscape(unit))
	b.WriteString(`</td><td class="num">` + invoiceEscape(money(billNumber(line, "amountMicros"))) + "</td></tr>")
	if len(tiers) > 1 {
		for _, tier := range tiers {
			label := "Units " + quantityText(billNumber(tier, "from"))
			if tier.Get("to") == nil {
				label += " and above"
			} else {
				label += "–" + quantityText(billNumber(tier, "to"))
			}
			b.WriteString(`<tr class="tier"><td>` + invoiceEscape(label))
			if truthy(tier.Get("flatAmountMicros")) {
				b.WriteString(`<div class="muted">` + invoiceEscape("plus "+money(billNumber(tier, "flatAmountMicros"))+" flat") + "</div>")
			}
			b.WriteString(`</td><td class="num">` + invoiceEscape(quantityText(billNumber(tier, "quantity"))))
			b.WriteString(`</td><td class="num">` + invoiceEscape(money(billNumber(tier, "unitAmountMicros"))))
			b.WriteString(`</td><td class="num">` + invoiceEscape(money(billNumber(tier, "amountMicros"))) + "</td></tr>")
		}
	}
	return b.String()
}

const invoiceStyle = `<style>
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111;margin:0;background:#f5f6f8}
main{max-width:800px;margin:24px auto;background:#fff;padding:40px;border-radius:8px}
h1{font-size:22px;margin:0}header{display:flex;justify-content:space-between;gap:24px;margin-bottom:32px}
.muted{color:#666;font-size:12px}.parties{display:flex;justify-content:space-between;gap:24px;margin-bottom:24px;font-size:14px}
table{width:100%;border-collapse:collapse;font-size:14px}th{text-align:left;border-bottom:1px solid #ddd;padding:8px 4px;font-weight:600}
td{padding:8px 4px;border-bottom:1px solid #f0f0f0;vertical-align:top}.num{text-align:right;white-space:nowrap}
tr.tier td{color:#555;font-size:12px;padding-left:20px}.totals{margin-left:auto;width:320px;margin-top:16px}
.totals td{border:none;padding:4px}.totals .strong td{font-weight:700;border-top:1px solid #ddd}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;background:#eef;font-size:12px}
.notes{margin-top:24px;font-size:13px;white-space:pre-wrap}@media print{body{background:#fff}main{margin:0;box-shadow:none}}
</style>`

// RenderInvoiceHtml (billing-invoices.ts renderInvoiceHtml): The invoice as a standalone HTML page (print it or save
// it as PDF): issuer, bill-to, number and dates, lines with tier sub-lines and service periods, discounts,
// commitment, credit, tax, payments, credit notes, and amount due. Options (nil for none): {issuer?, appName?,
// creditNotes?, now?}; `now` is the caller's Date.now() (the server's wall clock), which tells an open invoice from
// an overdue one (default: the system clock).
func RenderInvoiceHtml(statement *core.Object, options *core.Object) (result string, err error) {
	if options == nil {
		options = core.NewObject()
	}
	money := invoiceMoney(jsString(statement.Get("currency")))
	issuer, _ := core.Normalize(options.Get("issuer")).(*core.Object)
	if issuer == nil {
		issuer = core.NewObject("name", coalesce(options.Get("appName"), "Better IAM"))
	}
	status := jsString(statement.Get("status"))
	title := "Invoice " + jsString(statement.Get("number"))
	if status == "draft" {
		title = "Draft invoice · " + jsString(statement.Get("period"))
	}
	type totalRow struct {
		label, value string
		strong       bool
	}
	totals := []totalRow{{"Subtotal", money(billNumber(statement, "subtotalMicros")), false}}
	if discount, ok := statement.Get("discount").(*core.Object); ok && discount != nil {
		totals = append(totals, totalRow{"Discount (" + jsString(discount.Get("percent")) + "%)", money(-billNumber(discount, "amountMicros")), false})
	}
	if commitment, ok := statement.Get("commitment").(*core.Object); ok && commitment != nil && billNumber(commitment, "trueUpMicros") > 0 {
		totals = append(totals, totalRow{"Minimum commitment (" + money(billNumber(commitment, "minimumMicros")) + ") true-up", money(billNumber(commitment, "trueUpMicros")), false})
	}
	for _, coupon := range billObjects(statement.Get("coupons")) {
		label := jsString(coupon.Get("name")) + " (" + jsString(coupon.Get("code")) + ")"
		if core.StrictEquals(coupon.Get("name"), coupon.Get("code")) {
			label = jsString(coupon.Get("code"))
		}
		totals = append(totals, totalRow{label, money(-billNumber(coupon, "amountMicros")), false})
	}
	if truthy(statement.Get("creditsMicros")) {
		totals = append(totals, totalRow{"Credit applied", money(-billNumber(statement, "creditsMicros")), false})
	}
	if tax, ok := statement.Get("tax").(*core.Object); ok && tax != nil {
		totals = append(totals, totalRow{jsString(tax.Get("label")) + " (" + jsString(tax.Get("ratePercent")) + "%)", money(billNumber(tax, "amountMicros")), false})
	}
	totals = append(totals, totalRow{"Total", money(billNumber(statement, "totalMicros")), true})
	if paid := amountPaid(statement); truthy(paid) {
		totals = append(totals, totalRow{"Paid", money(-paid), false})
	}
	if truthy(statement.Get("creditNotesMicros")) {
		totals = append(totals, totalRow{"Credit notes", money(-billNumber(statement, "creditNotesMicros")), false})
	}
	totals = append(totals, totalRow{"Amount due", money(amountDue(statement)), true})
	billTo, _ := statement.Get("billTo").(*core.Object)
	if billTo == nil {
		billTo = core.NewObject()
	}
	badge := ""
	if status == "finalized" {
		now := float64(core.NowMillis())
		if at, ok := billNumberOf(options.Get("now")); ok {
			now = at
		}
		badge = "Open"
		if billNumber(statement, "dueAt") < now {
			badge = "Overdue"
		}
	} else if status != "" {
		units := core.ToUTF16(status)
		badge = strings.ToUpper(core.FromUTF16(units[:1])) + core.FromUTF16(units[1:])
	}
	block := func(lines ...any) string {
		parts := []string{}
		for _, line := range lines {
			if text, ok := line.(string); ok && text != "" {
				parts = append(parts, strings.ReplaceAll(invoiceEscape(text), "\n", "<br>"))
			}
		}
		return strings.Join(parts, "<br>")
	}
	optional := func(record *core.Object, key, prefix string) any {
		if value := record.Get(key); truthy(value) {
			return prefix + jsString(value)
		}
		return core.Undefined
	}
	emails := orgStrings(billTo, "emails")
	var emailLine any = core.Undefined
	if joined := strings.Join(emails, ", "); joined != "" {
		emailLine = joined
	}
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>` + invoiceEscape(title) + `</title><meta name="viewport" content="width=device-width, initial-scale=1">`)
	b.WriteString(invoiceStyle)
	b.WriteString("</head><body><main>\n")
	b.WriteString(`<header><div><h1>` + invoiceEscape(title) + `</h1><div class="muted">` +
		invoiceEscape(jsString(statement.Get("period"))+" · issued "+invoiceDay(billNumber(statement, "issuedAt"))+" · due "+invoiceDay(billNumber(statement, "dueAt"))) +
		`</div></div><div><span class="badge">` + invoiceEscape(badge) + "</span></div></header>\n")
	b.WriteString(`<section class="parties"><div><strong>` + invoiceEscape(jsString(issuer.Get("name"))) + "</strong><br>" +
		block(issuer.Get("address"), optional(issuer, "taxId", "Tax ID "), issuer.Get("email"), issuer.Get("url")) + "</div>\n")
	b.WriteString(`<div><span class="muted">Bill to</span><br><strong>` + invoiceEscape(jsString(coalesce(billTo.Get("companyName"), billTo.Get("name")))) + "</strong><br>" +
		block(billTo.Get("address"), optional(billTo, "taxId", "Tax ID "), optional(billTo, "purchaseOrder", "PO "), optional(billTo, "costCenter", "Cost center "), emailLine) +
		"</div></section>\n")
	b.WriteString(`<table><thead><tr><th>Description</th><th class="num">Quantity</th><th class="num">Unit price</th><th class="num">Amount</th></tr></thead><tbody>` + "\n")
	rows := []string{}
	for _, line := range billObjects(statement.Get("lines")) {
		rows = append(rows, lineRows(line, money))
	}
	b.WriteString(strings.Join(rows, "\n"))
	b.WriteString("\n</tbody></table>\n")
	b.WriteString(`<table class="totals"><tbody>`)
	for _, row := range totals {
		if row.strong {
			b.WriteString(`<tr class="strong">`)
		} else {
			b.WriteString("<tr>")
		}
		b.WriteString("<td>" + invoiceEscape(row.label) + `</td><td class="num">` + invoiceEscape(row.value) + "</td></tr>")
	}
	b.WriteString("</tbody></table>\n")
	if payments := billObjects(statement.Get("payments")); len(payments) > 0 {
		b.WriteString("<h3>Payments</h3><table><tbody>")
		for _, payment := range payments {
			reference := ""
			if truthy(payment.Get("reference")) {
				reference = " · " + invoiceEscape(jsString(payment.Get("reference")))
			}
			b.WriteString("<tr><td>" + invoiceEscape(invoiceDay(billNumber(payment, "receivedAt"))) + "</td><td>" + invoiceEscape(jsString(payment.Get("method"))) + reference +
				`</td><td class="num">` + invoiceEscape(money(billNumber(payment, "amountMicros"))) + "</td></tr>")
		}
		b.WriteString("</tbody></table>")
	}
	b.WriteString("\n")
	if notes := billObjects(core.Normalize(options.Get("creditNotes"))); len(notes) > 0 {
		b.WriteString("<h3>Credit notes</h3><table><tbody>")
		for _, note := range notes {
			memo := ""
			if truthy(note.Get("memo")) {
				memo = " · " + invoiceEscape(jsString(note.Get("memo")))
			}
			b.WriteString("<tr><td>" + invoiceEscape(jsString(note.Get("number"))) + "</td><td>" + invoiceEscape(strings.Replace(jsString(note.Get("reason")), "_", " ", 1)) + memo +
				`</td><td class="num">` + invoiceEscape(money(billNumber(note, "amountMicros"))) + "</td></tr>")
		}
		b.WriteString("</tbody></table>")
	}
	b.WriteString("\n")
	if instructions := issuer.Get("paymentInstructions"); truthy(instructions) {
		b.WriteString(`<div class="notes">` + invoiceEscape(jsString(instructions)) + "</div>")
	}
	b.WriteString("\n")
	if hash := statement.Get("hash"); truthy(hash) {
		b.WriteString(`<p class="muted">Content hash ` + invoiceEscape(jsString(hash)) + "</p>")
	}
	b.WriteString("\n</main></body></html>")
	return b.String(), nil
}
