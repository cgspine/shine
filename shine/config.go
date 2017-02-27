package shine

import (
	"os"
	"io/ioutil"
	"encoding/json"
	"strings"
	"time"
)

type Config struct {
	Server     string `json:"server"`
	ServerPort int        `json:"server_port"`
	LocalPort  int `json:"local_port"`
	Password   string `json:"password"`
	Method     string `json:"method"` // default: aes-256-cfb
	Timeout    int `json:"timeout"`   // default: 15
}

var readTimeout time.Duration

func ParseConfig(path string) (config *Config, err error) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}
	config = &Config{
		Method:  "aes-256-cfb",
		Timeout: 15,
	}
	if err = json.Unmarshal(data, config); err != nil {
		return nil, err
	}
	readTimeout = time.Duration(config.Timeout) * time.Second
	config.Method = strings.ToLower(config.Method)
	return
}
