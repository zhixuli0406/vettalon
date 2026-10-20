package main

import (
	"fmt"

	"github.com/tidwall/gjson"
)

type lookup struct {
	get func(string, string) gjson.Result
}

func main() {
	// The function value travels through a channel and a struct field.
	values := make(chan func(string, string) gjson.Result, 1)
	values <- gjson.Get
	holder := lookup{get: <-values}
	fmt.Println(holder.get(`{"a":{"b":1}}`, "a.b").Int())
}
