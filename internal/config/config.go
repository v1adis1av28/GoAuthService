package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DB struct {
		URL string `yaml:"url"`
	} `yaml:"db"`
	Server struct {
		Port string `yaml:"port"`
	} `yaml:"server"`
	JWT struct {
		Secret string `yaml:"secret"`
	} `yaml:"jwt"`
}

func Load() (*Config, error) {
	configPath := getConfigPath("configs/dev.yml")
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open config file")
	}
	defer file.Close()
	var cfg Config
	if err := yaml.NewDecoder(file).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config")
	}

	return &cfg, nil
}

func getConfigPath(defaultPath string) string {
	_, b, _, _ := runtime.Caller(0)
	baseDir := filepath.Dir(b)

	possiblePaths := []string{
		filepath.Join(baseDir, "../../", defaultPath),
		filepath.Join("/app", defaultPath),
		defaultPath,
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return defaultPath
}
