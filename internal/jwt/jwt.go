package jwt

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// var jwtSecretKey = []byte(os.Getenv("JWT_SECRET"))
var jwtSecretKey = []byte("sss")

// Возвращаем строку jwt токена по совместительству который является access токеном
func GenerateNewJwtKey(sub, userAgentInfo string) (string, error) {
	hashedUserAgent := sha256.Sum256([]byte(userAgentInfo))
	payload := jwt.MapClaims{
		"sub": sub,
		"exp": time.Now().Add(time.Minute * 5).Unix(),
		"ua":  base64.StdEncoding.EncodeToString(hashedUserAgent[:]),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, payload)

	t, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", err
	}
	return t, nil
}

func ExtractUUIDFromClaims(tokenStr string) (string, error) {
	hmacSecret := jwtSecretKey
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return hmacSecret, nil
	})
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		sub, err := claims.GetSubject()
		if err != nil {
			return "", fmt.Errorf("not found sub in jwt claims")
		}
		return sub, nil
	} else {
		log.Printf("Invalid JWT Token")
		return "", fmt.Errorf("invalid jwt token")
	}
}

func ExtractUAFromClaims(tokenStr string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return jwtSecretKey, nil
	})
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		ua, ok := claims["ua"].(string)
		if !ok {
			return "", fmt.Errorf("User Agent claim not found")
		}
		return ua, nil
	}
	return "", fmt.Errorf("invalid token")
}
