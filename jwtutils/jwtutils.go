package jwtutils

import (
	"github.com/golang-jwt/jwt"
)

type UserInterface interface {
	UserID() string
	UserType() string
}

func GenerateToken(user UserInterface) (string, error) {
	secret := "secret"

	var token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":       "mastertime",
		"uid":       user.UserID(),
		"user-type": user.UserType(),
	})

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
