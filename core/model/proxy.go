package model

// ProxyOutbound — прокси-выход, импортированный из ключа пользователя
// (ссылка vless://, hysteria2://…, подписка, Clash YAML).
type ProxyOutbound struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	// Source — "manual" или идентификатор подписки.
	Source string `json:"source"`
	// URI — исходный ключ; содержит секреты, поэтому никогда не отдаётся в API.
	URI string `json:"-"`
}
