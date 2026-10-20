package main

import (
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
)

func main() {
	fmt.Println(jwt.MapClaims{"iss": "issuer"}.VerifyIssuer("issuer", true))
}
