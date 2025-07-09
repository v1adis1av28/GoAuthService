package auth

import (
	"GoAuthService/internal/jwt"
	"GoAuthService/internal/models"
	"GoAuthService/internal/repository/user"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"
)

var tokenByteSize = 20

type UserService struct {
	repo *user.UserRepository
}

func (u *UserService) DeleteAllTokens(guid string) error {
	return u.repo.DeleteAllUserTokens()
}

func (u *UserService) UpdateIp(guid string, currentIp string) error {
	return u.repo.UpdateIp(guid, currentIp)
}

func NewUserService(repo *user.UserRepository) *UserService {
	return &UserService{repo: repo}
}

func (u *UserService) GetUserByUUID(uuid string) (*models.User, error) {
	return u.repo.FindUserByUUID(uuid)
}

func (u *UserService) CreateNewUser(userGuid, userAgentInfo, ip string) (*models.User, *models.Tokens, error) {
	accessToken, err := jwt.GenerateNewJwtKey(userGuid, userAgentInfo)
	if err != nil {
		return nil, nil, err
	}
	refreshToken, err := generateRefreshToken()
	if err != nil {
		return nil, nil, err
	}

	tokens := &models.Tokens{AccessToken: accessToken,
		RefreshToken: refreshToken}
	user := &models.User{
		GUID:               userGuid,
		HashedRefreshToken: refreshToken,
	}
	hashedRefreshToken, _ := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	err = u.repo.CreateNewUser(user.GUID, string(hashedRefreshToken), ip)
	if err != nil {
		return nil, nil, err
	}
	return user, tokens, nil
}

func (u *UserService) Logout(guid string) error {
	return u.repo.DeleteRefreshToken(guid)
}

func generateRefreshToken() (string, error) {
	token := make([]byte, tokenByteSize)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(token), nil
}

func (u *UserService) GenerateNewTokenPair(guid, userAgent string) (string, string, error) {
	accessToken, err := jwt.GenerateNewJwtKey(guid, userAgent)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := generateRefreshToken()
	if err != nil {
		return "", "", err
	}

	hashedAccess := sha256.Sum256([]byte(accessToken))
	hashedRefresh, _ := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)

	err = u.repo.SaveTokenPair(guid, string(hashedAccess[:]), string(hashedRefresh))
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
