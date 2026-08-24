package message

import (
	"bytes"
	"encoding/base64"
	"fmt"
	stdhtml "html"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"sort"
	"strings"

	xhtml "golang.org/x/net/html"
)

type Message struct {
	Headers   map[string][]string
	Body      strings.Builder
	Truncated bool
	MaxBytes  int64
	size      int64
}

func New(maxBytes int64) *Message {
	return &Message{Headers: make(map[string][]string), MaxBytes: maxBytes}
}
func (m *Message) AddHeader(name, value string) {
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	m.size += int64(len(name) + len(value) + 2)
	if m.size > m.MaxBytes {
		m.Truncated = true
		return
	}
	m.Headers[name] = append(m.Headers[name], value)
}
func (m *Message) AddBody(p []byte) {
	remaining := m.MaxBytes - m.size
	if remaining <= 0 {
		m.Truncated = true
		return
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
		m.Truncated = true
	}
	m.size += int64(len(p))
	_, _ = m.Body.Write(p)
}
func (m *Message) Header(name string) string {
	for k, v := range m.Headers {
		if strings.EqualFold(k, name) {
			return strings.Join(v, ", ")
		}
	}
	return ""
}

func (m *Message) Prompt(maxChars int) string {
	wanted := map[string]bool{"from": true, "reply-to": true, "return-path": true, "to": true, "subject": true, "date": true, "message-id": true, "authentication-results": true, "received-spf": true, "content-type": true}
	keys := make([]string, 0, len(m.Headers))
	for k := range m.Headers {
		if wanted[strings.ToLower(k)] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("SELECTED HEADERS:\n")
	for _, k := range keys {
		for _, v := range m.Headers[k] {
			fmt.Fprintf(&b, "%s: %s\n", sanitize(k), sanitize(v))
		}
	}
	body := extractText(m.Header("Content-Type"), m.Header("Content-Transfer-Encoding"), []byte(m.Body.String()), 0)
	body = strings.ToValidUTF8(body, "�")
	if len([]rune(body)) > maxChars {
		body = string([]rune(body)[:maxChars]) + "\n[body truncated]"
	}
	b.WriteString("\nBODY:\n")
	b.WriteString(body)
	return b.String()
}
func sanitize(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " ")
}

func extractText(contentType, encoding string, data []byte, depth int) string {
	if depth > 8 {
		return "[MIME nesting limit reached]"
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType == "" {
		mediaType = "text/plain"
	}
	decoded := decodeTransfer(encoding, data)
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return "[multipart message has no boundary]"
		}
		mr := multipart.NewReader(bytes.NewReader(decoded), boundary)
		var parts []string
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			b, _ := io.ReadAll(io.LimitReader(p, 2<<20))
			text := extractText(p.Header.Get("Content-Type"), p.Header.Get("Content-Transfer-Encoding"), b, depth+1)
			if strings.TrimSpace(text) != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "\n\n")
	}
	if mediaType != "text/plain" && mediaType != "text/html" {
		return "[attachment: " + sanitize(params["name"]) + "; type=" + mediaType + "]"
	}
	out := string(decoded)
	if mediaType == "text/html" {
		out = htmlToText(out)
	}
	return out
}

func htmlToText(source string) string {
	doc, err := xhtml.Parse(strings.NewReader(source))
	if err != nil {
		return stdhtml.UnescapeString(source)
	}
	var b strings.Builder
	writeHTMLText(&b, doc)
	return strings.Join(strings.Fields(stdhtml.UnescapeString(b.String())), " ")
}

func writeHTMLText(b *strings.Builder, n *xhtml.Node) {
	if n.Type == xhtml.ElementNode && (n.Data == "script" || n.Data == "style" || n.Data == "noscript") {
		return
	}
	if n.Type == xhtml.TextNode {
		b.WriteString(n.Data)
		b.WriteByte(' ')
		return
	}
	if n.Type == xhtml.ElementNode && n.Data == "a" {
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			writeHTMLText(b, child)
		}
		if href := htmlAttribute(n, "href"); href != "" {
			b.WriteString("[link: ")
			b.WriteString(sanitize(href))
			b.WriteString("] ")
		}
		return
	}
	if n.Type == xhtml.ElementNode {
		switch n.Data {
		case "br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6":
			b.WriteByte(' ')
		}
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		writeHTMLText(b, child)
	}
}

func htmlAttribute(n *xhtml.Node, name string) string {
	for _, attr := range n.Attr {
		if strings.EqualFold(attr.Key, name) {
			return strings.TrimSpace(attr.Val)
		}
	}
	return ""
}
func decodeTransfer(encoding string, data []byte) []byte {
	var r io.Reader = bytes.NewReader(data)
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, r)
	case "quoted-printable":
		r = quotedprintable.NewReader(r)
	}
	b, err := io.ReadAll(io.LimitReader(r, 2<<20))
	if err != nil {
		return data
	}
	return b
}
