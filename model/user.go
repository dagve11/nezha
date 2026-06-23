package model

import (
	"time"

	"github.com/gorilla/websocket"
	"github.com/nezhahq/nezha/pkg/utils"
	"gorm.io/gorm"
)

type Role uint8

func (r Role) IsAdmin() bool {
	return r == RoleAdmin
}

const (
	RoleAdmin Role = iota
	RoleMember
)

const DefaultAgentSecretLength = 32

type UserFeature string

const (
	UserFeatureService        UserFeature = "service"
	UserFeatureTask           UserFeature = "task"
	UserFeatureNotification   UserFeature = "notification"
	UserFeatureDDNS           UserFeature = "ddns"
	UserFeatureBestIP         UserFeature = "bestip"
	UserFeatureNAT            UserFeature = "nat"
	UserFeatureVPN            UserFeature = "vpn"
	UserFeatureServerGroup    UserFeature = "server_group"
	UserFeatureServerTransfer UserFeature = "server_transfer"
)

type UserPermissions struct {
	Service        bool `json:"service" gorm:"not null;default:true"`
	Task           bool `json:"task" gorm:"not null;default:false"`
	Notification   bool `json:"notification" gorm:"not null;default:true"`
	DDNS           bool `json:"ddns" gorm:"not null;default:false"`
	BestIP         bool `json:"bestip" gorm:"not null;default:false"`
	NAT            bool `json:"nat" gorm:"not null;default:false"`
	VPN            bool `json:"vpn" gorm:"not null;default:false"`
	ServerGroup    bool `json:"server_group" gorm:"not null;default:true"`
	ServerTransfer bool `json:"server_transfer" gorm:"not null;default:false"`
}

func DefaultUserPermissions(role Role) UserPermissions {
	if role.IsAdmin() {
		return UserPermissions{
			Service:        true,
			Task:           true,
			Notification:   true,
			DDNS:           true,
			BestIP:         true,
			NAT:            true,
			VPN:            true,
			ServerGroup:    true,
			ServerTransfer: true,
		}
	}

	return UserPermissions{
		Service:      true,
		Notification: true,
		ServerGroup:  true,
	}
}

type User struct {
	Common
	Username       string          `json:"username,omitempty" gorm:"uniqueIndex"`
	Password       string          `json:"password,omitempty" gorm:"type:char(72)"`
	Role           Role            `json:"role,omitempty"`
	AgentSecret    string          `json:"agent_secret,omitempty" gorm:"type:char(32)"`
	RejectPassword bool            `json:"reject_password,omitempty"`
	Permissions    UserPermissions `json:"permissions" gorm:"embedded;embeddedPrefix:permission_"`
	TokenVersion   uint64          `json:"-" gorm:"not null;default:0"`
}

type UserInfo struct {
	Role        Role
	Username    string
	AgentSecret string
	Permissions UserPermissions
}

func (u *User) HasFeature(feature UserFeature) bool {
	if u == nil {
		return false
	}
	if u.Role.IsAdmin() {
		return true
	}

	switch feature {
	case UserFeatureService:
		return u.Permissions.Service
	case UserFeatureTask:
		return u.Permissions.Task
	case UserFeatureNotification:
		return u.Permissions.Notification
	case UserFeatureDDNS:
		return u.Permissions.DDNS
	case UserFeatureBestIP:
		return u.Permissions.BestIP
	case UserFeatureNAT:
		return u.Permissions.NAT
	case UserFeatureVPN:
		return u.Permissions.VPN
	case UserFeatureServerGroup:
		return u.Permissions.ServerGroup
	case UserFeatureServerTransfer:
		return u.Permissions.ServerTransfer
	default:
		return false
	}
}

func (u *User) BeforeSave(tx *gorm.DB) error {
	if u.AgentSecret != "" {
		return nil
	}

	key, err := utils.GenerateRandomString(DefaultAgentSecretLength)
	if err != nil {
		return err
	}

	u.AgentSecret = key
	return nil
}

type Profile struct {
	User
	LoginIP    string            `json:"login_ip,omitempty"`
	Oauth2Bind map[string]string `json:"oauth2_bind,omitempty"`
}

type OnlineUser struct {
	UserID      uint64    `json:"user_id,omitempty"`
	ConnectedAt time.Time `json:"connected_at,omitempty"`
	IP          string    `json:"ip,omitempty"`

	Conn *websocket.Conn `json:"-"`
}
