package singleton

import (
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/nezhahq/nezha/model"
)

func MarkServersDeleted(tx *gorm.DB, servers []*model.Server) error {
	if len(servers) == 0 {
		return nil
	}

	rows := make([]model.DeletedServer, 0, len(servers))
	for _, server := range servers {
		if server == nil || server.UUID == "" {
			continue
		}
		rows = append(rows, model.DeletedServer{
			Common:   model.Common{UserID: server.GetUserID()},
			ServerID: server.ID,
			UUID:     server.UUID,
			Name:     server.Name,
		})
	}
	if len(rows) == 0 {
		return nil
	}

	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "uuid"}},
		DoNothing: true,
	}).Create(&rows).Error
}

func IsServerUUIDDeleted(uuid string) (bool, error) {
	if uuid == "" || DB == nil {
		return false, nil
	}
	var tombstone model.DeletedServer
	err := DB.Select("id").Where("uuid = ?", uuid).First(&tombstone).Error
	if err == nil {
		return true, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	return false, err
}
