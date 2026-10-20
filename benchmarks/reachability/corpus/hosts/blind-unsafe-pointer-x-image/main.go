package main

import (
	"bytes"
	"fmt"
	"image"
	"io"
	"unsafe"

	"golang.org/x/image/tiff"
)

func encoded() *bytes.Buffer {
	var buffer bytes.Buffer
	if err := tiff.Encode(&buffer, image.NewGray(image.Rect(0, 0, 2, 2)), nil); err != nil {
		panic(err)
	}
	return &buffer
}

type decodeFunc func(io.Reader) (image.Image, error)

func main() {
	// The function value is laundered through an untyped pointer word.
	original := decodeFunc(tiff.Decode)
	word := *(*unsafe.Pointer)(unsafe.Pointer(&original))
	var decode decodeFunc
	*(*unsafe.Pointer)(unsafe.Pointer(&decode)) = word
	decoded, err := decode(encoded())
	fmt.Println(decoded.Bounds(), err)
}
