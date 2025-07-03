package util

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func CheckUserAgent(c *gin.Context, tokenString string) bool {
	currUserAgent := sha256.Sum256([]byte(c.GetHeader("User-Agent")))
	hashedUserAgent := base64.StdEncoding.EncodeToString(currUserAgent[:])

	token, _ := jwt.Parse(tokenString, nil)
	claims, _ := token.Claims.(jwt.MapClaims)
	storedUserAgent, _ := claims["ua"].(string)

	return storedUserAgent == hashedUserAgent
}

func CheckUAIdentity(currentUA, UAFromClaim string) bool {
	currentHashingUA := sha256.Sum256([]byte(currentUA))
	hashCurrentUA := base64.StdEncoding.EncodeToString(currentHashingUA[:])

	if hashCurrentUA == UAFromClaim {
		return true
	}

	return false
}
