package message

import (
	"strings"
	"testing"
)

func TestPromptDecodesMultipart(t *testing.T) {
	m := New(10000)
	m.AddHeader("Subject", "Test")
	m.AddHeader("Content-Type", `multipart/alternative; boundary="x"`)
	m.AddBody([]byte("--x\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--x--\r\n"))
	p := m.Prompt(1000)
	if !strings.Contains(p, "hello") {
		t.Fatalf("decoded text missing: %s", p)
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
	if !strings.Contains(p, "abc\n[body truncated]") {
		t.Fatalf("not truncated: %s", p)
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
