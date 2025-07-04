package handlers

import (
	"GoAuthService/internal/jwt"
	"GoAuthService/internal/models"
	"GoAuthService/internal/service/auth"
	"GoAuthService/internal/util"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

const UuidPattern = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

type UserHandler struct {
	service *auth.UserService
}

func NewUserHandler(service *auth.UserService) *UserHandler {
	return &UserHandler{service: service}
}

// @Summary Выход из системы
// @Description Инвалидация текущих токенов пользователя
// @Tags Auth
// @Security BearerAuth
// @Accept json
// @Produce json
// @Success 200 {object} object{message=string} "Пример: {"message":"Logout successfuly!"}"
// @Failure 401 {object} models.ErrorResponse "Пример: {"message":"access token not found"}"
// @Failure 500 {object} models.ErrorResponse "Пример: {"message":"logout failed"}"
// @Router /logout [post]
func (h *UserHandler) Logout(c *gin.Context) {
	if len(c.GetHeader("Authorization")) == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "you are not authorize"})
		return
	}

	if !strings.HasPrefix(c.GetHeader("Authorization"), "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format, token should have `Bearer ` prefix"})
		return
	}

	accessToken := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if accessToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "access token not found"})
		return
	}

	uuid, err := jwt.ExtractUUIDFromClaims(accessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	err = h.service.Logout(uuid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Logout successfuly!"})

}

// @Summary Получить пару токенов
// @Description Получение access и refresh токенов. Если пользователя нет - он создается.
// @Tags Auth
// @Accept json
// @Produce json
// @Param guid query string true "User GUID" format(uuid) example(16763be4-6022-406e-a950-fcd5018633ca)
// @Success 200 {object} models.Tokens "Пример: {"access_token":"eyJ...","refresh_token":"bmV3IHJlZnJlc..."}"
// @Header 200 {string} Authorization "Пример: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..."
// @Failure 400 {object} models.ErrorResponse "Пример: {"message":"Wrong uuid input","info":"you must enter a 36-character uuid"}"
// @Failure 500 {object} models.ErrorResponse "Пример: {"message":"Database error","error":"connection refused"}"
// @Router /token [get]
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
	userAgent := c.GetHeader("User-Agent")
	if err != nil {
		if err.Error() == "user with that uuid not found" {
			//передаем заголовок user-agent для запрета обновления токенов при изменении этого заголовка
			ip := c.ClientIP()
			fmt.Println(ip)
			_, tokens, createErr := h.service.CreateNewUser(userGuid, userAgent, ip)
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
	accessToken, refreshToken, err := h.service.GenerateNewTokenPair(user.GUID, userAgent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to generate token pair", "error": err.Error()})
		return
	}

	c.Header("Authorization", "Bearer "+accessToken)
	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// @Summary Обновить токены
// @Description Обновление пары токенов по refresh токену
// @Tags Auth
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.Tokens true "Refresh token"
// @Success 200 {object} models.Tokens "Пример: {"access_token":"eyJ...","refresh_token":"bmV3IHJlZnJlc..."}"
// @Failure 403 {object} models.ErrorResponse "Пример: {"message":"wrong pair of tokens"}"
// @Failure 409 {object} models.ErrorResponse "Пример: {"message":"error you changed user-agent content"}"
// @Failure 500 {object} models.ErrorResponse "Пример: {"message":"token generation error"}"
// @Router /refresh [post]
func (h *UserHandler) RefreshTokens(c *gin.Context) {
	accessToken := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if accessToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "access token not found"})
		return
	}
	userInfo, err := jwt.ExtractUUIDFromClaims(accessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	user, err := h.service.GetUserByUUID(userInfo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	userAgent, err := jwt.ExtractUAFromClaims(accessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	if !util.CheckUAIdentity(c.GetHeader("User-Agent"), userAgent) {
		h.Logout(c)
		c.JSON(http.StatusConflict, gin.H{"message": "error you changed user-agent content"})
		return
	}

	currentIp := c.ClientIP()
	if isIpChanged(user.LastUserIp, currentIp) {
		go h.sendWebhook(user.GUID, user.LastUserIp, currentIp)
	}

	var refreshToken struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := c.ShouldBindJSON(&refreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error while getting refresh token"})
		return
	}

	tokenErr := bcrypt.CompareHashAndPassword([]byte(user.HashedRefreshToken), []byte(refreshToken.RefreshToken))
	if tokenErr != nil {
		c.JSON(http.StatusForbidden, gin.H{"message": "wrong pair of tokens"})
		return
	}
	newAccess, newRefresh, err := h.service.GenerateNewTokenPair(user.GUID, userAgent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"access_token":  newAccess,
		"refresh_token": newRefresh,
	})
}

// webhook который отсылает пост запрос на сервер, где обнавляется значение ip пользователя
func (h *UserHandler) sendWebhook(userGuid string, last_ip string, currentIp string) {
	payload := map[string]interface{}{
		"event":     "ip_change",
		"user_guid": userGuid,
		"old_ip":    last_ip,
		"new_ip":    currentIp,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	jsonData, _ := json.Marshal(payload)
	_, err := http.Post(
		"http://localhost:8080/changeIp",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		log.Printf("Failed to send webhook: %v", err)
	}
}

func isIpChanged(lastUserIp, currentIp string) bool {
	if lastUserIp != "" && lastUserIp != currentIp {
		return true
	}
	return false

}

func (h *UserHandler) UpdateIp(c *gin.Context) {
	var payload models.IpPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error while updating ip"})
		return
	}

	err := h.service.UpdateIp(payload.User_guid, payload.New_ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "ip was successfuly updated"})
}

// @Summary Получить GUID
// @Description Получение GUID текущего авторизованного пользователя
// @Tags User
// @Security BearerAuth
// @Accept json
// @Produce json
// @Success 200 {object} object "Пример: {"uuid":"16763be4-6022-406e-a950-fcd5018633ca"}"
// @Failure 401 {object} models.ErrorResponse "Пример: {"error":"Invalid token format, token should have `Bearer ` prefix"}"
// @Failure 500 {object} models.ErrorResponse "Пример: {"message":"failed to extract claims"}"
// @Router /guid [get]
func (h *UserHandler) GetUserGUID(c *gin.Context) {
	if !strings.HasPrefix(c.GetHeader("Authorization"), "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format, token should have `Bearer ` prefix"})
		return
	}

	accessToken := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if accessToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "access token not found"})
		return
	}

	uuid, err := jwt.ExtractUUIDFromClaims(accessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"uuid": uuid})
}
