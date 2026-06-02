package singleton

import (
	"os"
	"strings"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/nezhahq/nezha/model"
)

func TestInitConfigFromPathRotatesJWTSecretKey(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "nezha-config-*.yaml")
	if err != nil {
		t.Fatalf("create temp config: %v", err)
	}
	if _, err := file.WriteString("jwt_secret_key: leaked-secret\nagent_secret_key: agent-secret\njwt_secret_key_last_rotated_version: v2.0.12\n"); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close temp config: %v", err)
	}

	originalConf := Conf
	originalVersion := Version
	originalTemplates := FrontendTemplates
	Version = "v2.0.13"
	FrontendTemplates = nil
	t.Cleanup(func() {
		Conf = originalConf
		Version = originalVersion
		FrontendTemplates = originalTemplates
	})

	if err := InitConfigFromPath(file.Name()); err != nil {
		t.Fatalf("init config: %v", err)
	}
	if Conf.JWTSecretKey == "leaked-secret" {
		t.Fatal("jwt_secret_key was not rotated")
	}
	if Conf.JWTSecretKeyLastRotatedVersion != model.JWTSecretKeyRotationBaselineVersion {
		t.Fatalf("jwt secret key marker = %q, want %q", Conf.JWTSecretKeyLastRotatedVersion, model.JWTSecretKeyRotationBaselineVersion)
	}

	saved, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	if strings.Contains(string(saved), "leaked-secret") {
		t.Fatalf("saved config still contains leaked jwt_secret_key: %s", saved)
	}
	if !strings.Contains(string(saved), "jwt_secret_key_last_rotated_version: v2.0.13") {
		t.Fatalf("saved config did not persist jwt secret key marker: %s", saved)
	}
}

func TestSetTSDBEnabledUsesDefaultPathWhenEnabling(t *testing.T) {
	originalConf := Conf
	Conf = &ConfigClass{Config: &model.Config{}}
	t.Cleanup(func() { Conf = originalConf })

	SetTSDBEnabled(true)

	if !Conf.TSDB.Enabled {
		t.Fatal("TSDB enabled flag was not set")
	}
	if Conf.TSDB.DataPath != DefaultTSDBDataPath {
		t.Fatalf("TSDB data path = %q, want %q", Conf.TSDB.DataPath, DefaultTSDBDataPath)
	}
}

func TestSetTSDBEnabledClearsPathWhenDisabling(t *testing.T) {
	originalConf := Conf
	Conf = &ConfigClass{Config: &model.Config{
		TSDB: model.TSDBConf{
			Enabled:  true,
			DataPath: "data/tsdb",
		},
	}}
	t.Cleanup(func() { Conf = originalConf })

	SetTSDBEnabled(false)

	if Conf.TSDB.Enabled {
		t.Fatal("TSDB enabled flag was not cleared")
	}
	if Conf.TSDB.DataPath != "" {
		t.Fatalf("TSDB data path = %q, want empty", Conf.TSDB.DataPath)
	}
}

func TestApplyTSDBConfigRestoresLegacyServiceHistoryTableWhenDisabling(t *testing.T) {
	originalConf := Conf
	originalDB := DB
	originalTSDB := TSDBShared
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	DB = db
	TSDBShared = nil
	Conf = &ConfigClass{Config: &model.Config{
		TSDB: model.TSDBConf{
			Enabled: false,
		},
	}}
	t.Cleanup(func() {
		Conf = originalConf
		DB = originalDB
		TSDBShared = originalTSDB
	})

	if err := ApplyTSDBConfig(); err != nil {
		t.Fatalf("apply TSDB config: %v", err)
	}
	if !DB.Migrator().HasTable(&model.ServiceHistory{}) {
		t.Fatal("service_histories table was not restored after disabling TSDB")
	}
}
