package main

import (
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

func main() {
	document, err := html.Parse(strings.NewReader("<p>fixture</p>"))
	fmt.Println(document.Type, err)
}
