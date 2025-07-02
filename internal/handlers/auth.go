package handlers

import (
	"GoAuthService/internal/service/auth"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
)

const UuidPattern = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

type UserHandler struct {
	service *auth.UserService
}

func NewUserHandler(service *auth.UserService) *UserHandler {
	return &UserHandler{service: service}
}

func Logout() {

}

func (h *UserHandler) GetTokenPair(c *gin.Context) {
	userGuid := c.Query("guid")
	if len(userGuid) != 36 {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Wrong uuid input", "info": "you must enter a 36-character uuid"})
		return
	}

	check, _ := regexp.Match(UuidPattern, []byte(userGuid))
	if !check {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Incorrectly entered uuid"})
		return
	}
	user, err := h.service.GetUserByUUID(userGuid)

	if err != nil {
		if err.Error() == "user with that uuid not found" {
			_, tokens, createErr := h.service.CreateNewUser(userGuid)
			if createErr != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to create user", "error": createErr.Error()})
				return
			}
			c.Header("Authorization", "Bearer "+tokens.AccessToken)
			c.JSON(http.StatusCreated, tokens)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Database error", "error": err.Error()})
		return
	}
	accessToken, refreshToken, err := h.service.GenerateNewTokenPair(user.GUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to generate token pair", "error": err.Error()})
		return
	}

	// Устанавливаем заголовок перед отправкой JSON
	c.Header("Authorization", "Bearer "+accessToken)
	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// функция для обновления токенов
func UpdateTokens() {

}

// функция получения GUID пользователя
func GetUserGUID() {

}
