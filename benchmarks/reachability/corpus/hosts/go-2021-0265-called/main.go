package main

import (
	"fmt"

	"github.com/tidwall/gjson"
)

func main() {
	fmt.Println(gjson.Get(`{"a":{"b":1}}`, "a.b").Int())
}
