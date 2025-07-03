package models

type User struct {
	Id                 int    `json:"id"`
	GUID               string `json:"uuid"`
	HashedRefreshToken string `json:"refreshToken"`
	LastUserIp         string `json:"ip"`
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type IpPayload struct {
	Event     string `json:"event"`
	User_guid string `json:"user_guid"`
	Old_ip    string `json:"old_ip"`
	New_ip    string `json:"new_ip"`
}
