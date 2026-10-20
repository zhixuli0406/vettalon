package main

import (
	"fmt"

	uuid "github.com/satori/go.uuid"
)

func main() {
	fmt.Println(uuid.FromStringOrNil("6ba7b810-9dad-11d1-80b4-00c04fd430c8").Version())
}
