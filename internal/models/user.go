package models

import "github.com/google/uuid"

type User struct {
	Id                 int       `json:"id"`
	GUID               uuid.UUID `json:"uuid"`
	HashedRefreshToken string    `json:"refreshToken"`
}
