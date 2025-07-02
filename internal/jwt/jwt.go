package jwt

import (
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
		"exp": time.Now().Add(time.Hour * 2).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, payload)

	t, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", err
	}
	return t, nil
}
