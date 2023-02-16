package middleware

import (
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
	"strings"
)

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header is missing", http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Authorization header is not of type Bearer", http.StatusBadRequest)
			return
		}
		tokenString := strings.Split(authHeader, " ")[1]
		if tokenString == "" {
			http.Error(w, "Authorization token is missing", http.StatusUnauthorized)
			return
		}
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte("secret"), nil // replace with your secret key
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid authorization token", http.StatusUnauthorized)
			return
		}
		// Call the next handler, which can be another middleware in the chain, or the final handler
		next.ServeHTTP(w, r)
	})
}
