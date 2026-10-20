package main

import (
	"fmt"

	"golang.org/x/net/html"
)

func main() {
	fmt.Println(html.EscapeString("<p>fixture</p>"))
}
