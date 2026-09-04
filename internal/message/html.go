package message

import (
	stdhtml "html"
	"strings"

	xhtml "golang.org/x/net/html"
)

func htmlToText(source string) extractedContent {
	doc, err := xhtml.Parse(strings.NewReader(source))
	if err != nil {
		text := stdhtml.UnescapeString(source)
		return extractedContent{Text: text, VisibleText: text, Links: findHTTPURLs(text)}
	}
	var b strings.Builder
	var links []string
	var imageRefs []string
	writeHTMLText(&b, &links, &imageRefs, doc)
	text := strings.Join(strings.Fields(stdhtml.UnescapeString(b.String())), " ")
	visibleText := htmlVisibleText(doc)
	links = append(links, findHTTPURLs(text)...)
	return extractedContent{Text: text, VisibleText: visibleText, Links: links, ImageRefs: imageRefs}
}

func htmlVisibleText(doc *xhtml.Node) string {
	var b strings.Builder
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n.Type == xhtml.ElementNode && (n.Data == "script" || n.Data == "style" || n.Data == "noscript") {
			return
		}
		block := false
		if n.Type == xhtml.ElementNode {
			switch n.Data {
			case "br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote":
				block = true
				b.WriteByte('\n')
			}
		}
		if n.Type == xhtml.TextNode {
			b.WriteString(n.Data)
			b.WriteByte(' ')
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
		if block {
			b.WriteByte('\n')
		}
	}
	walk(doc)
	lines := strings.Split(stdhtml.UnescapeString(b.String()), "\n")
	clean := lines[:0]
	for _, line := range lines {
		if line = strings.Join(strings.Fields(line), " "); line != "" {
			clean = append(clean, line)
		}
	}
	return strings.Join(clean, "\n")
}

func writeHTMLText(b *strings.Builder, links, imageRefs *[]string, n *xhtml.Node) {
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
			writeHTMLText(b, links, imageRefs, child)
		}
		if href := htmlAttribute(n, "href"); href != "" {
			b.WriteString("[link: ")
			b.WriteString(sanitize(href))
			b.WriteString("] ")
			*links = append(*links, href)
		}
		return
	}
	if n.Type == xhtml.ElementNode && n.Data == "img" {
		if src := htmlAttribute(n, "src"); len(src) > 4 && strings.EqualFold(src[:4], "cid:") {
			*imageRefs = append(*imageRefs, normalizeContentID(src[4:]))
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
		writeHTMLText(b, links, imageRefs, child)
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
