package message

import (
	"bytes"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"strings"
)

func selectVisionImages(content extractedContent, options VisionOptions) []Image {
	if options.Mode == "off" || options.MaxImages < 1 || options.MaxBytes < 1 || options.MaxPixels < 1 {
		return nil
	}
	if options.Mode == "fallback" && len([]rune(strings.TrimSpace(content.VisibleText))) >= options.MinTextChars {
		return nil
	}
	referenced := make(map[string]bool, len(content.ImageRefs))
	for _, ref := range content.ImageRefs {
		if ref != "" {
			referenced[ref] = true
		}
	}
	selected := make([]Image, 0, min(options.MaxImages, len(content.Images)))
	for _, candidate := range content.Images {
		if len(selected) >= options.MaxImages {
			break
		}
		if candidate.ContentID == "" || !referenced[candidate.ContentID] || int64(len(candidate.Data)) > options.MaxBytes {
			continue
		}
		imageConfig, format, err := image.DecodeConfig(bytes.NewReader(candidate.Data))
		if err != nil || imageConfig.Width < 1 || imageConfig.Height < 1 || int64(imageConfig.Width) > options.MaxPixels/int64(imageConfig.Height) {
			continue
		}
		mediaType := map[string]string{"jpeg": "image/jpeg", "png": "image/png", "gif": "image/gif"}[format]
		if mediaType == "" {
			continue
		}
		selected = append(selected, Image{MediaType: mediaType, Data: candidate.Data})
	}
	return selected
}
