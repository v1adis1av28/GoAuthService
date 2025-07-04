package models

type User struct {
	Id                 int    `json:"id"`
	GUID               string `json:"uuid"`
	HashedRefreshToken string `json:"refreshToken"`
	LastUserIp         string `json:"ip"`
}

// Tokens represents JWT token pair
// @name Tokens
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// IpPayload represents IP change data
// @name IpPayload
type IpPayload struct {
	Event     string `json:"event"`
	User_guid string `json:"user_guid"`
	Old_ip    string `json:"old_ip"`
	New_ip    string `json:"new_ip"`
}

// ErrorResponse represents standard error format
// @name ErrorResponse
type ErrorResponse struct {
	Message string `json:"message" example:"error description"`
	Info    string `json:"info,omitempty" example:"additional info"`
}
