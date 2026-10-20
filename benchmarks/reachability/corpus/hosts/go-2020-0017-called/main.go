package main

import (
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
)

func main() {
	fmt.Println(jwt.MapClaims{"aud": "service"}.VerifyAudience("service", true))
}
