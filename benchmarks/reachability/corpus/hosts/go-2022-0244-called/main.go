package main

import (
	"fmt"

	uuid "github.com/satori/go.uuid"
)

func main() {
	value, err := uuid.NewV4()
	fmt.Println(value.Version(), err)
}
