package main

import (
	"bytes"
	"fmt"
	"image"

	"golang.org/x/image/tiff"
)

func encoded() *bytes.Buffer {
	var buffer bytes.Buffer
	if err := tiff.Encode(&buffer, image.NewGray(image.Rect(0, 0, 2, 2)), nil); err != nil {
		panic(err)
	}
	return &buffer
}

func main() {
	decoded, err := tiff.Decode(encoded())
	fmt.Println(decoded.Bounds(), err)
}
