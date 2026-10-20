package main

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "fixture"})
	signed, err := token.SignedString([]byte("fixture-key-not-a-secret"))
	fmt.Println(len(signed) > 0, err)
}
