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
	links = append(links, findHTTPURLs(text)...)
	return extractedContent{Text: text, VisibleText: text, Links: links, ImageRefs: imageRefs}
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
