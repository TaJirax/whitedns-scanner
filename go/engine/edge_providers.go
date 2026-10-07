package engine

// The original nine service domains and the platform mappings are reused from
// WhiteDNS-cleanip-finder/internal/scanner/ips.go and internal/config/edge.go.
type EdgeProvider struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Modes           []string `json:"modes"`
	DefaultPorts    []int    `json:"defaultPorts"`
	Hint            string   `json:"hint"`
	Hosts           []string `json:"hosts"`
	PlatformDomains []string `json:"platformDomains"`
	ProbeDomains    []string `json:"probeDomains"`
}

func DefaultProbeDomains() []string {
	return []string{"workers.dev", "pages.dev", "gemini.google.com", "notebooklm.google.com", "instagram.com", "chatgpt.com", "web.telegram.org", "reddit.com", "claude.ai"}
}

func ProbeDomainsForPlatform(platform []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, d := range append(append([]string(nil), platform...), DefaultProbeDomains()[2:]...) {
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

func EdgeProviders() []EdgeProvider {
	out := []EdgeProvider{
		{ID: "cloudflare", Name: "Cloudflare (CDN / Workers)", Modes: []string{"http", "http-all", "custom"}, DefaultPorts: []int{443, 80}, Hint: "Existing Cloudflare defaults and service checks are preserved.", Hosts: []string{"speed.marisalnc.com", "cloudflare.182682.xyz", "rapid-lake-4bce.zajrvcwp.workers.dev", "freeyx.cloudflare88.eu.org", "bestcf.top", "cdn.2020111.xyz", "cfip.cfcdn.vip", "cf.0sm.com", "cf.090227.xyz", "cf.zhetengsha.eu.org", "cloudflare.9jy.cc", "cf.zerone-cdn.pp.ua", "cfip.1323123.xyz", "cnamefuckxxs.yuchen.icu", "cloudflare-ip.mofashi.ltd", "115155.xyz", "cname.xirancdn.us", "f3058171cad.002404.xyz", "8.889288.xyz", "cdn.tzpro.xyz", "cf.877771.xyz", "xn--b6gac.eu.org"}, PlatformDomains: []string{"workers.dev", "pages.dev"}},
		{ID: "cloudflare-pages", Name: "Cloudflare Pages (pages.dev)", Modes: []string{"http", "http-all", "custom"}, DefaultPorts: []int{443, 80}, Hint: "Existing Cloudflare defaults and service checks are preserved.", Hosts: []string{"pages.cloudflare.com", "developers.cloudflare.com", "blog.cloudflare.com", "dash.cloudflare.com"}, PlatformDomains: []string{"pages.dev", "pages.cloudflare.com", "workers.dev"}},
		{ID: "render", Name: "Render (onrender.com)", Modes: []string{"http", "custom"}, DefaultPorts: []int{443, 80}, Hint: "Uses the platform domains from your existing Edge domains configuration, with the seven common service tests unchanged.", Hosts: []string{"render.com", "www.render.com", "dashboard.render.com", "docs.render.com", "api.render.com", "community.render.com"}, PlatformDomains: []string{"onrender.com", "render.com"}},
		{ID: "fly", Name: "Fly.io (fly.dev)", Modes: []string{"http", "custom"}, DefaultPorts: []int{443, 80}, Hint: "Uses the platform domains from your existing Edge domains configuration, with the seven common service tests unchanged.", Hosts: []string{"fly.io", "www.fly.io", "fly.dev", "community.fly.io", "api.machines.dev"}, PlatformDomains: []string{"fly.dev", "fly.io"}},
		{ID: "railway", Name: "Railway (up.railway.app)", Modes: []string{"http", "custom"}, DefaultPorts: []int{443, 80}, Hint: "Uses the platform domains from your existing Edge domains configuration, with the seven common service tests unchanged.", Hosts: []string{"railway.com", "railway.app", "docs.railway.com", "backboard.railway.app", "up.railway.app"}, PlatformDomains: []string{"up.railway.app", "railway.app", "railway.com"}},
		{ID: "vercel", Name: "Vercel (vercel.app)", Modes: []string{"http", "custom"}, DefaultPorts: []int{443, 80}, Hint: "Uses the platform domains from your existing Edge domains configuration, with the seven common service tests unchanged.", Hosts: []string{"vercel.com", "www.vercel.com", "vercel.app", "vercel.live", "react.dev", "nextjs.org", "sdk.vercel.ai"}, PlatformDomains: []string{"vercel.app", "vercel.com", "react.dev", "nextjs.org"}},
		{ID: "netlify", Name: "Netlify (netlify.app)", Modes: []string{"http", "custom"}, DefaultPorts: []int{443, 80}, Hint: "Uses the platform domains from your existing Edge domains configuration, with the seven common service tests unchanged.", Hosts: []string{"netlify.com", "www.netlify.com", "netlify.app", "docs.netlify.com", "app.netlify.com", "api.netlify.com"}, PlatformDomains: []string{"netlify.app", "netlify.com", "docs.netlify.com"}},
		{ID: "koyeb", Name: "Koyeb (koyeb.app)", Modes: []string{"http", "custom"}, DefaultPorts: []int{443, 80}, Hint: "Uses the platform domains from your existing Edge domains configuration, with the seven common service tests unchanged.", Hosts: []string{"koyeb.com", "www.koyeb.com", "app.koyeb.com", "koyeb.app"}, PlatformDomains: []string{"koyeb.app", "koyeb.com"}},
		{ID: "glitch", Name: "Glitch (glitch.com)", Modes: []string{"http", "custom"}, DefaultPorts: []int{443, 80}, Hint: "Uses the platform domains from your existing Edge domains configuration, with the seven common service tests unchanged.", Hosts: []string{"glitch.com", "www.glitch.com", "blog.glitch.com", "cdn.glitch.me"}, PlatformDomains: []string{"glitch.com", "cdn.glitch.me"}},
		{ID: "fastly", Name: "Fastly", Modes: []string{"http", "custom"}, DefaultPorts: []int{443, 80}, Hint: "Uses the platform domains from your existing Edge domains configuration, with the seven common service tests unchanged.", Hosts: []string{"fastly.com", "python.org", "pypi.org", "reddit.com", "githubusercontent.com", "githubassets.com"}, PlatformDomains: []string{"fastly.com", "python.org", "pypi.org"}},
		{ID: "akamai", Name: "Akamai", Modes: []string{"http", "custom"}, DefaultPorts: []int{443, 80}, Hint: "Uses the platform domains from your existing Edge domains configuration, with the seven common service tests unchanged.", Hosts: []string{"www.akamai.com", "techdocs.akamai.com"}, PlatformDomains: []string{"akamai.com", "techdocs.akamai.com"}},
		{ID: "custom", Name: "Other / custom CDN", Modes: []string{"http", "custom"}, DefaultPorts: []int{443, 80}, Hint: "Uses the platform domains from your existing Edge domains configuration, with the seven common service tests unchanged.", Hosts: []string{}, PlatformDomains: []string{}},
	}
	for i := range out {
		out[i].ProbeDomains = ProbeDomainsForPlatform(out[i].PlatformDomains)
	}
	return out
}

func FindEdgeProvider(id string) (EdgeProvider, bool) {
	for _, p := range EdgeProviders() {
		if p.ID == id {
			return p, true
		}
	}
	return EdgeProvider{}, false
}
