package model

type NATForm struct {
	Name      string `json:"name,omitempty" minLength:"1"`
	Enabled   bool   `json:"enabled,omitempty"`
	ServerID  uint64 `json:"server_id,omitempty"`
	Host      string `json:"host,omitempty"`
	LocalPort uint16 `json:"local_port,omitempty"`
	Port      uint16 `json:"port,omitempty"`
}
