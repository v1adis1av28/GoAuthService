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

func (h *UserHandler) Logout(c *gin.Context) {
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

// TODO дореализовать на получение GUID текущего пользователя (роут должен быть защищен);
// функция получения GUID пользователя
func GetUserGUID() {

}
