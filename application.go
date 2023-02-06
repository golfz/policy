package main

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/mastertech-hq/authority/jwtutils"
	"time"
)

type CustomClaims struct {
	Uid       string `json:"uid"`
	UserType  string `json:"user_type"`
	TokenType string `json:"token_type"`
}

func main() {
	customClaims := CustomClaims{
		Uid:       "d7dded03-833f-453a-9e26-860244a475bf",
		UserType:  "employee",
		TokenType: "access",
	}
	token, err := jwtutils.GenerateToken(customClaims, 6*time.Second, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(token)

	time.Sleep(2 * time.Second)

	_, err = jwtutils.ParseToken(token)
	if err != nil {
		fmt.Println(err)
		if errors.Is(err, jwt.ErrTokenExpired) {
			fmt.Println(">>>> token expired")
		}
		return
	}

	us, err := jwtutils.GetCustomClaimString(token, "uid")
	if err != nil {
		fmt.Println(">>>> custom claims not ok", err)
		return
	}

	fmt.Printf(">>>> claims: %+v\n", us)

}
