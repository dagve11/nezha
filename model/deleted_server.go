package model

type DeletedServer struct {
	Common

	ServerID uint64 `gorm:"index" json:"server_id"`
	UUID     string `gorm:"uniqueIndex;not null" json:"uuid"`
	Name     string `json:"name"`
}
