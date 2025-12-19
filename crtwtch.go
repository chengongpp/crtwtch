package main

import (
	"crypto/tls"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Version int          `toml:"version"`
	Groups  []WatchGroup `toml:"groups"`
}

type WatchGroup struct {
	Name                string   `toml:"name"`
	WxworkToken         string   `toml:"wxwork_token"`
	Interval            int      `toml:"interval"`
	DayBeforeExpiration int      `toml:"redline"`
	Sites               []string `toml:"sites"`
}

//go:embed config.example.toml
var defaultTemplate string

const WxworkMsgTplInfo = `
{
	"msgtype": "text",
	"text": {
		"content": "%s"
	}
}
`

func (g *WatchGroup) SendWxwork(msg string, level slog.Level) error {
	payload := fmt.Sprintf(WxworkMsgTplInfo, msg)
	if g.WxworkToken == "" {
		slog.Warn("wxwork_token is empty, skipping wxwork notification", "group", g.Name)
		return nil
	}
	req, err := http.NewRequest("POST", "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key="+g.WxworkToken, strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	slog.Info("post", "url", req.URL.String(), "data", payload)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		slog.Error("wxwork notification failed", "status_code", resp.StatusCode, "group", g.Name)
		return fmt.Errorf("wxwork notification failed with status code: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	slog.Info("body", "response", string(body))
	slog.Info("wxwork notification sent successfully", "group", g.Name, "level", level.String())
	return nil
}

func main() {
	gen := flag.Bool("g", false, "generate default config")
	conf := flag.String("c", "config.toml", "config file path")
	flag.Parse()

	if *gen {
		if fi, _ := os.Stat("config.example.toml"); fi != nil && !fi.IsDir() {
			fmt.Println("config.example.toml already exists")
			fmt.Println("override? [y/n]")
			var input string
			_, _ = fmt.Scanln(&input)
			if input == "y" || input == "Y" || strings.ToLower(input) == "yes" {
				_ = os.WriteFile("config.example.toml", []byte(defaultTemplate), 0644)
				fmt.Println("generated config.example.toml")
			}
		} else {
			_ = os.WriteFile("config.example.toml", []byte(defaultTemplate), 0644)
		}
		return
	}
	if fi, err := os.Stat(*conf); err != nil || fi.IsDir() {
		slog.Error("config file not found:", "config", *conf)
		os.Exit(1)
	}

	config := Config{}
	_, err := toml.DecodeFile(*conf, &config)
	if err != nil {
		slog.Error("failed to parse config file:", "error", err)
		os.Exit(1)
	}
	//TODO: daemon(cron) mode. You have to use crond or systemd timer to run periodically
	for _, group := range config.Groups {
		slog.Info("watching group:", "name", group.Name)
		today := time.Now()
		alerts := make([]string, 0)
		for _, site := range group.Sites {
			slog.Info("checking site:", "site", site)
			expire, err := GetExpirationDate(site)
			if err != nil {
				slog.Error("failed to check cert:", "site", site, "error", err)
				alerts = append(alerts, fmt.Sprintf("❗ 检测失败: %s", site))
				continue
			}
			daysLeft := int(expire.Sub(today).Hours() / 24)
			slog.Info("site checked:", "site", site, "expire", expire.Format("2006-01-02"), "days_left", daysLeft)
			if daysLeft <= group.DayBeforeExpiration && daysLeft >= 0 {
				alerts = append(alerts, fmt.Sprintf("⚠️ 证书即将过期: %s 还有 %d 天 (到期日: %s)", site, daysLeft, expire.Format("2006-01-02")))
			} else if daysLeft < 0 {
				alerts = append(alerts, fmt.Sprintf("❗ 证书已过期: %s (到期日: %s)", site, expire.Format("2006-01-02")))
			}
		}
		if len(alerts) <= 0 {
			slog.Info("no alerts to send")
			text := fmt.Sprintf("✅ [%s] 组 %s 的证书监控正常，共 %d 个", time.Now().Format("2006-01-02"), group.Name, len(group.Sites))
			group.SendWxwork(text, slog.LevelInfo)
		} else {
			slog.Info("sending alerts", "count", len(alerts))
			text := fmt.Sprintf("🚨 [%s] 组 %s 的证书监控发现 %d 个问题:\n%s", time.Now().Format("2006-01-02"), group.Name, len(alerts), strings.Join(alerts, "\n"))
			group.SendWxwork(text, slog.LevelWarn)
		}
	}
}

func GetExpirationDate(host string) (time.Time, error) {
	// Check certificate expiration date
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	conn, err := tls.Dial("tcp", host, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return time.Time{}, fmt.Errorf("no certificates found")
	}
	return certs[0].NotAfter, nil
}
