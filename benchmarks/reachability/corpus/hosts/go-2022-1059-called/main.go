package main

import (
	"fmt"

	"golang.org/x/text/language"
)

func main() {
	tags, weights, err := language.ParseAcceptLanguage("en-US,fr;q=0.8")
	fmt.Println(len(tags), len(weights), err)
}
