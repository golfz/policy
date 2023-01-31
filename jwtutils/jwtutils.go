package jwtutils

import (
	"github.com/golang-jwt/jwt/v4"
	"os"
	"time"
)

type UserInterface interface {
	UserID() string
	UserType() string
}

type JWTData struct {
	jwt.RegisteredClaims
	CustomClaims map[string]string `json:"custom_claims"`
}

func GenerateToken(user UserInterface) (string, error) {
	secret := os.Getenv("JWT_SECRET")

	claims := JWTData{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
		},
		CustomClaims: map[string]string{
			"uid":       user.UserID(),
			"user_type": user.UserType(),
		},
	}

	var token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
