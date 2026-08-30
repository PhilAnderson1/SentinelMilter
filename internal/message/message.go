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
	"net/url"
	"regexp"
	"sort"
	"strings"

	xhtml "golang.org/x/net/html"
)

type Message struct {
	Headers    map[string][]string
	Body       strings.Builder
	Truncated  bool
	MaxBytes   int64
	bodySize   int64
	headerSize int64
}

const (
	maxRetainedHeaderBytes = 32 << 10
	maxHeaderValueBytes    = 8 << 10
	maxExtractedLinks      = 100
	maxExtractedLinkChars  = 8192
	maxExtractedLinkLength = 2048
)

var retainedHeaders = map[string]bool{
	"authentication-results":    true,
	"content-transfer-encoding": true,
	"content-type":              true,
	"date":                      true,
	"from":                      true,
	"message-id":                true,
	"received-spf":              true,
	"reply-to":                  true,
	"return-path":               true,
	"subject":                   true,
	"to":                        true,
}

var promptHeaders = map[string]bool{
	"authentication-results": true,
	"content-type":           true,
	"date":                   true,
	"from":                   true,
	"message-id":             true,
	"received-spf":           true,
	"reply-to":               true,
	"return-path":            true,
	"subject":                true,
	"to":                     true,
}

var plainHTTPURL = regexp.MustCompile(`(?i)https?://[^\s<>"'\]\)]+`)

func New(maxBytes int64) *Message {
	return &Message{Headers: make(map[string][]string), MaxBytes: maxBytes}
}
func (m *Message) AddHeader(name, value string) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !retainedHeaders[name] {
		return
	}
	value = strings.TrimSpace(value)
	if len(value) > maxHeaderValueBytes {
		value = value[:maxHeaderValueBytes]
		m.Truncated = true
	}
	entrySize := int64(len(name) + len(value) + 2)
	if m.headerSize+entrySize > maxRetainedHeaderBytes {
		m.Truncated = true
		return
	}
	m.headerSize += entrySize
	m.Headers[name] = append(m.Headers[name], value)
}
func (m *Message) AddBody(p []byte) {
	remaining := m.MaxBytes - m.bodySize
	if remaining <= 0 {
		m.Truncated = true
		return
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
		m.Truncated = true
	}
	m.bodySize += int64(len(p))
	_, _ = m.Body.Write(p)
}
func (m *Message) Header(name string) string {
	return strings.Join(m.Headers[strings.ToLower(name)], ", ")
}

func (m *Message) Prompt(maxChars int) string {
	keys := make([]string, 0, len(m.Headers))
	for k := range m.Headers {
		if promptHeaders[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("SELECTED HEADERS:\n")
	for _, k := range keys {
		for _, v := range m.Headers[k] {
			fmt.Fprintf(&b, "%s: %s\n", canonicalHeaderName(k), sanitize(v))
		}
	}
	content := extractText(m.Header("Content-Type"), m.Header("Content-Transfer-Encoding"), []byte(m.Body.String()), 0)
	body := strings.ToValidUTF8(content.Text, "�")
	body = sampleBody(body, maxChars)
	b.WriteString("\nBODY:\n")
	b.WriteString(body)
	if links := boundedLinks(content.Links); len(links) > 0 {
		b.WriteString("\n\nEXTRACTED LINKS (retained independently of body sampling):\n")
		for _, link := range links {
			fmt.Fprintf(&b, "- %s\n", sanitize(link))
		}
	}
	return b.String()
}

func canonicalHeaderName(name string) string {
	parts := strings.Split(name, "-")
	for i, part := range parts {
		if part != "" {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, "-")
}
func sanitize(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " ")
}

func sampleBody(body string, maxChars int) string {
	runes := []rune(body)
	if len(runes) <= maxChars {
		return body
	}
	if maxChars < 6 {
		head := (maxChars + 1) / 2
		return string(runes[:head]) + "\n[... body omitted ...]\n" + string(runes[len(runes)-(maxChars-head):]) + "\n[body truncated; beginning and end retained]"
	}

	headCount := maxChars / 2
	middleCount := maxChars / 4
	tailCount := maxChars - headCount - middleCount
	middleStart := (len(runes) - middleCount) / 2
	tailStart := len(runes) - tailCount
	return string(runes[:headCount]) +
		"\n[... body section omitted ...]\n" +
		string(runes[middleStart:middleStart+middleCount]) +
		"\n[... body section omitted ...]\n" +
		string(runes[tailStart:]) +
		"\n[body truncated; beginning, middle, and end retained]"
}

func findHTTPURLs(text string) []string {
	matches := plainHTTPURL.FindAllString(text, maxExtractedLinks*2)
	links := make([]string, 0, len(matches))
	for _, match := range matches {
		links = append(links, strings.TrimRight(match, ".,;:!?}"))
	}
	return links
}

func boundedLinks(candidates []string) []string {
	seen := make(map[string]bool)
	links := make([]string, 0, min(len(candidates), maxExtractedLinks))
	chars := 0
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		parsed, err := url.Parse(candidate)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || seen[candidate] {
			continue
		}
		candidateChars := len([]rune(candidate))
		if candidateChars > maxExtractedLinkLength || chars+candidateChars > maxExtractedLinkChars {
			continue
		}
		if len(links) >= maxExtractedLinks {
			break
		}
		seen[candidate] = true
		links = append(links, candidate)
		chars += candidateChars
	}
	return links
}

type extractedContent struct {
	Text  string
	Links []string
}

func extractText(contentType, encoding string, data []byte, depth int) extractedContent {
	if depth > 8 {
		return extractedContent{Text: "[MIME nesting limit reached]"}
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType == "" {
		mediaType = "text/plain"
	}
	decoded := decodeTransfer(encoding, data)
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return extractedContent{Text: "[multipart message has no boundary]"}
		}
		mr := multipart.NewReader(bytes.NewReader(decoded), boundary)
		var parts []extractedContent
		var alternativeHTML extractedContent
		var alternativePlain extractedContent
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			b, _ := io.ReadAll(io.LimitReader(p, 2<<20))
			partContentType := p.Header.Get("Content-Type")
			content := extractText(partContentType, p.Header.Get("Content-Transfer-Encoding"), b, depth+1)
			if strings.TrimSpace(content.Text) != "" {
				parts = append(parts, content)
				if mediaType == "multipart/alternative" {
					partMediaType, _, _ := mime.ParseMediaType(partContentType)
					switch partMediaType {
					case "text/html":
						alternativeHTML = content
					case "text/plain":
						alternativePlain = content
					}
				}
			}
		}
		if mediaType == "multipart/alternative" {
			if strings.TrimSpace(alternativeHTML.Text) != "" {
				return alternativeHTML
			}
			if strings.TrimSpace(alternativePlain.Text) != "" {
				return alternativePlain
			}
			if len(parts) > 0 {
				return parts[len(parts)-1]
			}
			return extractedContent{}
		}
		var textParts []string
		var links []string
		for _, part := range parts {
			textParts = append(textParts, part.Text)
			links = append(links, part.Links...)
		}
		return extractedContent{Text: strings.Join(textParts, "\n\n"), Links: links}
	}
	if mediaType != "text/plain" && mediaType != "text/html" {
		return extractedContent{Text: "[attachment: " + sanitize(params["name"]) + "; type=" + mediaType + "]"}
	}
	out := string(decoded)
	if mediaType == "text/html" {
		return htmlToText(out)
	}
	return extractedContent{Text: out, Links: findHTTPURLs(out)}
}

func htmlToText(source string) extractedContent {
	doc, err := xhtml.Parse(strings.NewReader(source))
	if err != nil {
		text := stdhtml.UnescapeString(source)
		return extractedContent{Text: text, Links: findHTTPURLs(text)}
	}
	var b strings.Builder
	var links []string
	writeHTMLText(&b, &links, doc)
	text := strings.Join(strings.Fields(stdhtml.UnescapeString(b.String())), " ")
	links = append(links, findHTTPURLs(text)...)
	return extractedContent{Text: text, Links: links}
}

func writeHTMLText(b *strings.Builder, links *[]string, n *xhtml.Node) {
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
			writeHTMLText(b, links, child)
		}
		if href := htmlAttribute(n, "href"); href != "" {
			b.WriteString("[link: ")
			b.WriteString(sanitize(href))
			b.WriteString("] ")
			*links = append(*links, href)
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
		writeHTMLText(b, links, child)
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
