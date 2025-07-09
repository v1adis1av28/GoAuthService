package user

import (
	"GoAuthService/internal/models"
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
)

type UserRepository struct {
	db *pgx.Conn
}

func (ur *UserRepository) DeleteAllUserTokens(guid string) error {
	_, err := ur.db.Exec(context.Background(), "DELETE FROM USER_TOKENS WHERE GUID = $1", guid)
	if err != nil {
		return err
	}
	return nil
}

func (ur *UserRepository) UpdateIp(guid string, currentIp string) error {
	_, err := ur.db.Exec(context.Background(), "UPDATE USERS SET last_ip = $1 WHERE guid = $2",
		currentIp, guid,
	)
	return err
}

func (ur *UserRepository) DeleteRefreshToken(guid string) error {
	sqlStatement := "UPDATE users SET hashed_refresh_token = '' WHERE guid = $1"
	result, err := ur.db.Exec(context.Background(), sqlStatement, guid)
	if err != nil {
		return fmt.Errorf("failed to delete refresh token")
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("wrong uuid")
	}
	return nil
}

func (ur *UserRepository) UpdateRefreshToken(guid string, hashed_token string) error {
	sqlStatemnt := "UPDATE USERS SET HASHED_REFRESH_TOKEN = $1 WHERE guid = $2"
	check, err := ur.db.Exec(context.Background(), sqlStatemnt, hashed_token, guid)
	if err != nil {
		return err
	}
	if check.RowsAffected() == 0 {
		return fmt.Errorf("user with that uuid not found")
	}
	return nil
}

func (ur *UserRepository) CreateNewUser(uuid, token, ip string) error {
	tx, err := ur.db.Begin(context.Background())
	if err != nil {
		return fmt.Errorf("Error on openning transaction")
	}
	defer tx.Rollback(context.Background())

	sqlStatement := "INSERT INTO USERS (guid,hashed_refresh_token,expires_at,last_ip) VALUES ($1,$2,$3,$4)"
	_, err = tx.Exec(context.Background(), sqlStatement, uuid, token, time.Now().Add(time.Hour*48), ip)
	if err != nil {
		return fmt.Errorf("Error while inserting new user in db")
	}
	if err := tx.Commit(context.Background()); err != nil {
		return fmt.Errorf("error commiting transaction")
	}
	log.Printf("creating new user successfuly")
	return nil
}

func (u *UserRepository) FindUserByUUID(uuid string) (*models.User, error) {
	sqlStatement := "SELECT u.guid, u.hashed_refresh_token, u.last_ip FROM USERS as u where u.guid = $1"
	var user models.User
	err := u.db.QueryRow(context.Background(), sqlStatement, uuid).Scan(&user.GUID, &user.HashedRefreshToken, &user.LastUserIp)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user with that uuid not found")
		}
	}
	return &user, nil
}

func NewUserRepository(db *pgx.Conn) *UserRepository {
	return &UserRepository{db: db}
}

func (ur *UserRepository) SaveTokenPair(userID, accessTokenHash, refreshTokenHash string) error {
	sqlstatment := "INSERT INTO user_tokens (user_id, access_token_hash, refresh_token_hash) VALUES ($1, $2, $3) ON CONFLICT (user_id) DO UPDATE SET access_token_hash = $2, refresh_token_hash = $3"
	_, err := ur.db.Exec(
		context.Background(), sqlstatment,
		userID, accessTokenHash, refreshTokenHash,
	)
	return err
}

func (ur *UserRepository) GetTokenPair(userID string) (accessTokenHash, refreshTokenHash string, err error) {
	err = ur.db.QueryRow(context.Background(),
		`SELECT access_token_hash, refresh_token_hash FROM user_tokens WHERE user_id = $1`,
		userID,
	).Scan(&accessTokenHash, &refreshTokenHash)
	return
}
