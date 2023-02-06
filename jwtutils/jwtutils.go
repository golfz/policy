package jwtutils

import (
	"github.com/golang-jwt/jwt/v4"
	"os"
	"time"
)

type JWTData struct {
	jwt.RegisteredClaims
	CustomClaims interface{} `json:"custom_claims"`
}

func GenerateToken(customClaims interface{}, tokenLifetime time.Duration, notBefore *time.Time) (string, error) {
	secret := os.Getenv("AUTH_JWT_SECRET")
	issuer := os.Getenv("AUTH_JWT_ISSUER")

	var nbf *jwt.NumericDate
	if notBefore != nil {
		nbf = jwt.NewNumericDate(*notBefore)
	}

	claims := JWTData{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: nbf,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenLifetime)),
			Issuer:    issuer,
		},
		CustomClaims: customClaims,
	}

	var token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ParseToken(tokenString string) (*JWTData, error) {
	secret := os.Getenv("AUTH_JWT_SECRET")

	token, err := jwt.ParseWithClaims(tokenString, &JWTData{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*JWTData)
	if !ok {
		return nil, err
	}

	return claims, nil
}

func GetCustomClaims(tokenString string) (interface{}, error) {
	claims, err := ParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	return claims.CustomClaims, nil
}

func GetCustomClaim(tokenString string, claimName string) (interface{}, error) {
	claims, err := ParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	return claims.CustomClaims.(map[string]interface{})[claimName], nil
}

func GetCustomClaimString(tokenString string, claimName string) (string, error) {
	claims, err := ParseToken(tokenString)
	if err != nil {
		return "", err
	}

	return claims.CustomClaims.(map[string]interface{})[claimName].(string), nil
}

func GetCustomClaimInt(tokenString string, claimName string) (int, error) {
	claims, err := ParseToken(tokenString)
	if err != nil {
		return 0, err
	}

	return int(claims.CustomClaims.(map[string]interface{})[claimName].(float64)), nil
}

func GetCustomClaimBool(tokenString string, claimName string) (bool, error) {
	claims, err := ParseToken(tokenString)
	if err != nil {
		return false, err
	}

	return claims.CustomClaims.(map[string]interface{})[claimName].(bool), nil
}

func GetCustomClaimTime(tokenString string, claimName string) (time.Time, error) {
	claims, err := ParseToken(tokenString)
	if err != nil {
		return time.Time{}, err
	}

	return time.Parse(time.RFC3339, claims.CustomClaims.(map[string]interface{})[claimName].(string))
}

func GetCustomClaimDuration(tokenString string, claimName string) (time.Duration, error) {
	claims, err := ParseToken(tokenString)
	if err != nil {
		return 0, err
	}

	return time.ParseDuration(claims.CustomClaims.(map[string]interface{})[claimName].(string))
}

func GetCustomClaimStringSlice(tokenString string, claimName string) ([]string, error) {
	claims, err := ParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	var stringSlice []string
	for _, value := range claims.CustomClaims.(map[string]interface{})[claimName].([]interface{}) {
		stringSlice = append(stringSlice, value.(string))
	}

	return stringSlice, nil
}

func GetCustomClaimIntSlice(tokenString string, claimName string) ([]int, error) {
	claims, err := ParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	var intSlice []int
	for _, value := range claims.CustomClaims.(map[string]interface{})[claimName].([]interface{}) {
		intSlice = append(intSlice, int(value.(float64)))
	}

	return intSlice, nil
}

func GetCustomClaimBoolSlice(tokenString string, claimName string) ([]bool, error) {
	claims, err := ParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	var boolSlice []bool
	for _, value := range claims.CustomClaims.(map[string]interface{})[claimName].([]interface{}) {
		boolSlice = append(boolSlice, value.(bool))
	}

	return boolSlice, nil
}

func GetCustomClaimTimeSlice(tokenString string, claimName string) ([]time.Time, error) {
	claims, err := ParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	var timeSlice []time.Time
	for _, value := range claims.CustomClaims.(map[string]interface{})[claimName].([]interface{}) {
		timeSlice = append(timeSlice, value.(time.Time))
	}

	return timeSlice, nil
}

func GetCustomClaimDurationSlice(tokenString string, claimName string) ([]time.Duration, error) {
	claims, err := ParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	var durationSlice []time.Duration
	for _, value := range claims.CustomClaims.(map[string]interface{})[claimName].([]interface{}) {
		durationSlice = append(durationSlice, value.(time.Duration))
	}

	return durationSlice, nil
}

func GetCustomClaimMap(tokenString string, claimName string) (map[string]interface{}, error) {
	claims, err := ParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	return claims.CustomClaims.(map[string]interface{})[claimName].(map[string]interface{}), nil
}
