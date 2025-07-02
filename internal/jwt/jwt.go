package jwt

import (
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// var jwtSecretKey = []byte(os.Getenv("JWT_SECRET"))
var jwtSecretKey = []byte("sss")

// Возвращаем строку jwt токена по совместительству который является access токеном
func GenerateNewJwtKey(sub string) (string, error) {
	//Генерируем полезную информацию в токене
	payload := jwt.MapClaims{
		"sub": sub,
		"exp": time.Now().Add(time.Minute * 5).Unix(),
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
