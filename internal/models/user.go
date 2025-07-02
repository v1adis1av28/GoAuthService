package models

type User struct {
	Id                 int    `json:"id"`
	GUID               string `json:"uuid"`
	HashedRefreshToken string `json:"refreshToken"`
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
