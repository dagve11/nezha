package model

type NAT struct {
	Common
	Enabled  bool   `json:"enabled"`
	Name     string `json:"name"`
	ServerID uint64 `json:"server_id"`
	Host     string `json:"host"`
	Port     uint16 `json:"port"`
}
