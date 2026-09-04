package message

import (
	"encoding/base64"
	"strings"
	"testing"
)

const onePixelPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="

func TestPromptDecodesMultipart(t *testing.T) {
	m := New(10000)
	m.AddHeader("Subject", "Test")
	m.AddHeader("Message-ID", "<test@example.invalid>")
	m.AddHeader("Content-Type", `multipart/alternative; boundary="x"`)
	m.AddBody([]byte("--x\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--x--\r\n"))
	p := m.Prompt(1000)
	if !strings.Contains(p, "hello") {
		t.Fatalf("decoded text missing: %s", p)
	}
	if strings.Contains(p, "Content-Type:") {
		t.Fatalf("MIME content type leaked into selected headers: %s", p)
	}
	if strings.Contains(p, "Message-Id:") {
		t.Fatalf("message ID leaked into selected headers: %s", p)
	}
}

func TestConnectionInformationPrecedesHeadersAndReportsDNSPrecisely(t *testing.T) {
	m := New(1000)
	m.Connection = ConnectionInfo{
		RemoteIP:            "92.205.185.174",
		MTAReportedHostname: "174.185.205.92.host.secureserver.net",
		HELOIdentity:        "mx.example.com",
		ReverseDNSStatus:    ReverseDNSAvailable,
		ReverseDNS: []ReverseDNSName{
			{Hostname: "174.185.205.92.host.secureserver.net", Confirmation: ForwardConfirmed},
			{Hostname: "other.example", Confirmation: ForwardUnconfirmed},
		},
	}
	m.AddHeader("Subject", "test")
	prompt := m.Prompt(100)
	for _, want := range []string{
		"CONNECTION INFORMATION:",
		"Remote IP: 92.205.185.174",
		"MTA-reported client hostname: 174.185.205.92.host.secureserver.net",
		"Reverse DNS: 174.185.205.92.host.secureserver.net (forward-confirmed), other.example (unconfirmed)",
		"Forward-confirmed reverse DNS: yes",
		"SMTP HELO/EHLO identity: mx.example.com",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q:\n%s", want, prompt)
		}
	}
	if strings.Index(prompt, "CONNECTION INFORMATION:") > strings.Index(prompt, "SELECTED HEADERS:") {
		t.Fatalf("connection information does not precede headers:\n%s", prompt)
	}
}

func TestConnectionInformationDistinguishesAbsentFailureAndUnavailable(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{ReverseDNSAbsent, "Reverse DNS: none\nForward-confirmed reverse DNS: not applicable"},
		{ReverseDNSLookupFailed, "Reverse DNS: lookup failed\nForward-confirmed reverse DNS: unknown"},
		{ReverseDNSNotApplicable, "Reverse DNS: not applicable\nForward-confirmed reverse DNS: not applicable"},
	}
	for _, test := range tests {
		m := New(100)
		m.Connection.ReverseDNSStatus = test.status
		prompt := m.Prompt(10)
		if !strings.Contains(prompt, "Remote IP: unavailable") || !strings.Contains(prompt, test.want) {
			t.Errorf("status %q formatted incorrectly:\n%s", test.status, prompt)
		}
	}
}

func TestConnectionInformationSanitizesAndBoundsUntrustedValues(t *testing.T) {
	m := New(100)
	m.Connection = ConnectionInfo{
		RemoteIP:            strings.Repeat("a", maxConnectionValueRunes+20) + "\nINJECTED:",
		MTAReportedHostname: "host.example\r\nSubject: forged",
		HELOIdentity:        "helo.example\x00bad",
	}
	prompt := m.Prompt(10)
	if strings.Contains(prompt, "\r") || strings.Contains(prompt, "\x00") || strings.Contains(prompt, "\nINJECTED:") || strings.Contains(prompt, "\nSubject: forged") {
		t.Fatalf("connection metadata was not sanitized:\n%s", prompt)
	}
}

func TestMultipartAlternativePrefersHTML(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", `multipart/alternative; boundary="x"`)
	m.AddBody([]byte("--x\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nplain-only wording\r\n" +
		"--x\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<p>HTML <a href=\"https://example.invalid/login\">sign in</a></p>\r\n" +
		"--x--\r\n"))
	prompt := m.Prompt(1000)
	if strings.Contains(prompt, "plain-only wording") {
		t.Fatalf("plain alternative must be ignored when HTML is available: %s", prompt)
	}
	if !strings.Contains(prompt, "HTML sign in [link: https://example.invalid/login]") {
		t.Fatalf("HTML alternative or link destination missing: %s", prompt)
	}
}

func TestMultipartAlternativeFallsBackToPlainText(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", `multipart/alternative; boundary="x"`)
	m.AddBody([]byte("--x\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nplain fallback\r\n--x--\r\n"))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, "plain fallback") {
		t.Fatalf("plain-text fallback missing: %s", prompt)
	}
}

func TestMultipartAlternativeAppliesLimitAfterSelection(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", `multipart/alternative; boundary="x"`)
	m.AddBody([]byte("--x\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + strings.Repeat("padding ", 500) + "\r\n" +
		"--x\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<p>short HTML body</p>\r\n" +
		"--x--\r\n"))
	prompt := m.Prompt(30)
	if !strings.Contains(prompt, "short HTML body") || strings.Contains(prompt, "[body truncated]") {
		t.Fatalf("limit was not applied after selecting the HTML alternative: %s", prompt)
	}
}

func TestPromptTruncates(t *testing.T) {
	m := New(10000)
	m.AddBody([]byte("abcdef"))
	p := m.Prompt(3)
	if !strings.Contains(p, "ab\n[... body omitted ...]\nf\n[body truncated; beginning and end retained]") {
		t.Fatalf("not truncated: %s", p)
	}
}

func TestHeaderPaddingCannotConsumeBodyBudget(t *testing.T) {
	m := New(128)
	for range 300 {
		m.AddHeader("Authentication-Results", strings.Repeat("padding", 200))
		m.AddHeader("X-Ignored-Padding", strings.Repeat("ignored", 1000))
	}
	body := "Your account is suspended. Sign in at https://evil.example/login"
	m.AddBody([]byte(body))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, body) {
		t.Fatalf("header padding consumed body allowance: %s", prompt)
	}
}

func TestLongBodySamplesBeginningMiddleAndEnd(t *testing.T) {
	m := New(10000)
	body := "BEGIN-EVIDENCE " + strings.Repeat("a", 400) + " MIDDLE-EVIDENCE " + strings.Repeat("b", 400) + " END-EVIDENCE"
	m.AddBody([]byte(body))
	prompt := m.Prompt(120)
	for _, evidence := range []string{"BEGIN-EVIDENCE", "MIDDLE-EVIDENCE", "END-EVIDENCE"} {
		if !strings.Contains(prompt, evidence) {
			t.Errorf("sampled prompt omitted %s: %s", evidence, prompt)
		}
	}
}

func TestLinkInventorySurvivesOmittedBodySection(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	link := "https://evil.example/steal-password"
	body := "<p>" + strings.Repeat("a", 200) + `<a href="` + link + `">verify</a>` + strings.Repeat("b", 800) + "</p>"
	m.AddBody([]byte(body))
	prompt := m.Prompt(100)
	if !strings.Contains(prompt, "EXTRACTED LINKS") || !strings.Contains(prompt, "- "+link) {
		t.Fatalf("independent link inventory omitted a link outside sampled text: %s", prompt)
	}
}

func TestLinkInventoryDoesNotDuplicateLinkRetainedInBody(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	link := "https://example.org/action"
	m.AddBody([]byte(`<p>Take action <a href="` + link + `">today</a>.</p>`))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, "[link: "+link+"]") {
		t.Fatalf("body omitted link destination: %s", prompt)
	}
	if strings.Contains(prompt, "EXTRACTED LINKS") {
		t.Fatalf("link retained in body was duplicated in extracted inventory: %s", prompt)
	}
}

func TestHTMLPreservesLinkTextAndDestination(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte(`<p>Sign in to <a href="https://evil.example/login"><strong>Microsoft</strong></a>.</p>`))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, "Sign in to Microsoft [link: https://evil.example/login] .") {
		t.Fatalf("link evidence missing: %s", prompt)
	}
}

func TestHTMLExcludesScriptAndStyle(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte(`<style>.hidden{display:none}</style><script>ignoreMe()</script><p>Visible</p>`))
	prompt := m.Prompt(1000)
	if strings.Contains(prompt, "ignoreMe") || strings.Contains(prompt, "display:none") {
		t.Fatalf("active HTML content leaked into prompt: %s", prompt)
	}
	if !strings.Contains(prompt, "Visible") {
		t.Fatalf("visible text missing: %s", prompt)
	}
}

func TestMalformedHTMLStillPreservesLink(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte(`<a href="https://example.invalid">Click <b>here`))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, "Click here [link: https://example.invalid]") {
		t.Fatalf("malformed HTML link missing: %s", prompt)
	}
}

func TestVisionFallbackSelectsReferencedInlineImage(t *testing.T) {
	m := imageOnlyMessage("cid:scam-image", "<scam-image>")
	analysis := m.BuildAnalysis(1000, VisionOptions{
		Mode: "fallback", MinTextChars: 200, MaxImages: 2,
		MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if len(analysis.Images) != 1 {
		t.Fatalf("selected images = %d, want 1; prompt=%s", len(analysis.Images), analysis.Prompt)
	}
	if analysis.Images[0].MediaType != "image/png" {
		t.Fatalf("media type = %q, want image/png", analysis.Images[0].MediaType)
	}
	if !strings.Contains(analysis.Prompt, "INLINE EMAIL IMAGES: 1") {
		t.Fatalf("vision disclosure missing from prompt: %s", analysis.Prompt)
	}
}

func TestVisionFallbackIgnoresUnreferencedImage(t *testing.T) {
	m := imageOnlyMessage("cid:different-image", "<scam-image>")
	analysis := m.BuildAnalysis(1000, VisionOptions{
		Mode: "fallback", MinTextChars: 200, MaxImages: 2,
		MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if len(analysis.Images) != 0 {
		t.Fatalf("selected unreferenced image: %#v", analysis.Images)
	}
}

func TestVisionOffAndRemoteImagesAreNeverSelected(t *testing.T) {
	inline := imageOnlyMessage("cid:scam-image", "<scam-image>")
	if images := inline.BuildAnalysis(1000, VisionOptions{
		Mode: "off", MinTextChars: 200, MaxImages: 2, MaxBytes: 1 << 20, MaxPixels: 100,
	}).Images; len(images) != 0 {
		t.Fatal("vision mode off selected an inline image")
	}

	remote := New(10000)
	remote.AddHeader("Content-Type", "text/html")
	remote.AddBody([]byte(`<img src="https://tracker.example/image.png">`))
	if images := remote.BuildAnalysis(1000, VisionOptions{
		Mode: "always", MaxImages: 2, MaxBytes: 1 << 20, MaxPixels: 100,
	}).Images; len(images) != 0 {
		t.Fatal("selected or fetched a remote image")
	}
}

func TestVisionFallbackSkipsImageWhenTextIsMeaningful(t *testing.T) {
	m := imageOnlyMessage("cid:scam-image", "<scam-image>")
	longText := strings.Repeat("This is meaningful body text. ", 20)
	m = multipartRelatedMessage(longText, `<p>`+longText+`</p><img src="cid:scam-image">`, "<scam-image>")
	analysis := m.BuildAnalysis(1000, VisionOptions{
		Mode: "fallback", MinTextChars: 200, MaxImages: 2,
		MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if len(analysis.Images) != 0 {
		t.Fatal("fallback mode selected an image despite sufficient visible text")
	}
}

func TestVisionImageLimitsAreEnforced(t *testing.T) {
	m := imageOnlyMessage("cid:scam-image", "<scam-image>")
	decoded, err := base64.StdEncoding.DecodeString(onePixelPNG)
	if err != nil {
		t.Fatal(err)
	}
	analysis := m.BuildAnalysis(1000, VisionOptions{
		Mode: "always", MaxImages: 1, MaxBytes: int64(len(decoded) - 1), MaxPixels: 100,
	})
	if len(analysis.Images) != 0 {
		t.Fatal("selected an image exceeding the byte limit")
	}
}

func imageOnlyMessage(src, contentID string) *Message {
	return multipartRelatedMessage("[7d4d-90d5-ef340]", `<img alt="7d4d-90d5-ef340" src="`+src+`">`, contentID)
}

func multipartRelatedMessage(plain, html, contentID string) *Message {
	m := New(1 << 20)
	m.AddHeader("Content-Type", `multipart/related; boundary="outer"`)
	body := "--outer\r\n" +
		"Content-Type: multipart/alternative; boundary=\"inner\"\r\n\r\n" +
		"--inner\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + plain + "\r\n" +
		"--inner\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<html><body>" + html + "</body></html>\r\n" +
		"--inner--\r\n" +
		"--outer\r\nContent-Type: image/png; name=notice.png\r\n" +
		"Content-ID: " + contentID + "\r\nContent-Disposition: inline\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + onePixelPNG + "\r\n" +
		"--outer--\r\n"
	m.AddBody([]byte(body))
	return m
}
