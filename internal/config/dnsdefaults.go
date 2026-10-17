package config

import coredns "tross/core/dns"

// DefaultUpstreams — серверы по умолчанию. Только по IP: DoH/DoT по имени
// сервера в России обрывают по SNI. Защищённый набор — узлы вне России без
// журналов, быстрый — быстрейшие из России. DNS провайдера нет: он видит
// имена и подменяет ответы заглушками блокировок.
func DefaultUpstreams() []Upstream {
	prot := []coredns.Pool{coredns.PoolProtected}
	fast := []coredns.Pool{coredns.PoolFast}
	return []Upstream{
		// Quad9 9.9.9.9 режет вредоносные домены; 9.9.9.10 — без фильтра,
		// запасной на случай ложной блокировки.
		{Name: "quad9", URL: "https://9.9.9.9/dns-query", Pools: []coredns.Pool{coredns.PoolProtected, coredns.PoolFast}, Backup: "quad9-unfiltered"},
		{Name: "mullvad", URL: "https://194.242.2.2/dns-query", Pools: prot, Backup: "dnssb"},
		{Name: "digitale", URL: "https://185.95.218.42/dns-query", Pools: prot, Backup: "dnssb"},
		{Name: "dns4eu", URL: "tls://86.54.11.100", Pools: prot, Backup: "dnssb"},
		{Name: "quad9-unfiltered", URL: "https://9.9.9.10/dns-query"},
		{Name: "dnssb", URL: "https://185.222.222.222/dns-query"},
		{Name: "cloudflare", URL: "https://1.1.1.1/dns-query", Pools: fast},
		{Name: "cloudflare-2", URL: "https://1.0.0.1/dns-query", Pools: fast},
		{Name: "google", URL: "https://8.8.4.4/dns-query", Pools: fast},
	}
}

// DefaultSensitive — особо личное по умолчанию: мессенджеры, спорные
// сервисы, почта, банки.
func DefaultSensitive() Sensitive {
	return Sensitive{
		Services: []string{"steam", "youtube", "discord"},
		Domains: []string{
			"telegram.org", "t.me", "telegram.me", "telegra.ph", "tdesktop.com", "telesco.pe", "cdn-telegram.org",
			"gmail.com", "googlemail.com", "mail.google.com",
			"proton.me", "protonmail.com", "outlook.com", "hotmail.com", "mail.ru", "mail.yandex.ru",
			"sberbank.ru", "sber.ru", "tbank.ru", "tinkoff.ru", "vtb.ru", "alfabank.ru", "gazprombank.ru",
			"raiffeisen.ru", "open.ru", "sovcombank.ru", "pochtabank.ru", "psbank.ru", "mtsbank.ru",
			"rshb.ru", "rosbank.ru",
		},
	}
}
