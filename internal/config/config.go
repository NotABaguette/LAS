package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const CurrentVersion = 1

type Config struct {
	Version    int            `json:"version"`
	Host       HostConfig     `json:"host"`
	UI         UIConfig       `json:"ui"`
	Interfaces []Interface    `json:"interfaces"`
	Tunnels    []Tunnel       `json:"tunnels"`
	Routing    RoutingConfig  `json:"routing"`
	Services   ServicesConfig `json:"services"`
	Security   SecurityConfig `json:"security"`
}

type HostConfig struct {
	Hostname        string   `json:"hostname"`
	ManagementCIDRs []string `json:"managementCIDRs"`
	EnableIPForward bool     `json:"enableIPForward"`
	ConntrackMax    int      `json:"conntrackMax"`
}

type UIConfig struct {
	Listen        string `json:"listen"`
	AdminUsername string `json:"adminUsername"`
	TLSCertFile   string `json:"tlsCertFile"`
	TLSKeyFile    string `json:"tlsKeyFile"`
}

type Interface struct {
	Name       string      `json:"name"`
	Role       string      `json:"role"`
	Enabled    bool        `json:"enabled"`
	Addresses  []string    `json:"addresses"`
	Gateway    string      `json:"gateway"`
	DNS        []string    `json:"dns"`
	MTU        int         `json:"mtu"`
	Masquerade bool        `json:"masquerade"`
	DHCPServer *DHCPServer `json:"dhcpServer,omitempty"`
}

type DHCPServer struct {
	RangeStart string   `json:"rangeStart"`
	RangeEnd   string   `json:"rangeEnd"`
	LeaseTime  string   `json:"leaseTime"`
	DNS        []string `json:"dns"`
	Domain     string   `json:"domain"`
}

type Tunnel struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Type           string            `json:"type"`
	Direction      string            `json:"direction"`
	Enabled        bool              `json:"enabled"`
	InterfaceName  string            `json:"interfaceName"`
	Mark           int               `json:"mark"`
	Table          int               `json:"table"`
	MTU            int               `json:"mtu"`
	RemoteEndpoint string            `json:"remoteEndpoint"`
	LocalAddresses []string          `json:"localAddresses"`
	DNS            []string          `json:"dns"`
	Credentials    map[string]string `json:"credentials"`
	Options        map[string]string `json:"options"`
}

type RoutingConfig struct {
	DefaultPolicy string        `json:"defaultPolicy"`
	Sets          []RouteSet    `json:"sets"`
	WANGroups     []WANGroup    `json:"wanGroups"`
	StaticRoutes  []StaticRoute `json:"staticRoutes"`
	Rules         []RouteRule   `json:"rules"`
}

type RouteSet struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Enabled     bool     `json:"enabled"`
	Description string   `json:"description"`
	Countries   []string `json:"countries"`
	CIDRs       []string `json:"cidrs"`
	Domains     []string `json:"domains"`
	SourceURLs  []string `json:"sourceUrls"`
	Refresh     string   `json:"refresh"`
}

type WANGroup struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	Enabled bool        `json:"enabled"`
	Mode    string      `json:"mode"`
	Mark    int         `json:"mark"`
	Table   int         `json:"table"`
	Members []WANMember `json:"members"`
}

type WANMember struct {
	Interface   string `json:"interface"`
	Gateway     string `json:"gateway"`
	Weight      int    `json:"weight"`
	Priority    int    `json:"priority"`
	Healthcheck string `json:"healthcheck"`
}

type StaticRoute struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Table       int    `json:"table"`
	Metric      int    `json:"metric"`
}

type RouteRule struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Enabled  bool       `json:"enabled"`
	Priority int        `json:"priority"`
	Match    RuleMatch  `json:"match"`
	Action   RuleAction `json:"action"`
}

type RuleMatch struct {
	InputIface       string      `json:"inputIface"`
	OutputIface      string      `json:"outputIface"`
	SourceCIDRs      []string    `json:"sourceCIDRs"`
	DestinationCIDRs []string    `json:"destinationCIDRs"`
	SourcePorts      []PortRange `json:"sourcePorts"`
	DestinationPorts []PortRange `json:"destinationPorts"`
	Protocols        []string    `json:"protocols"`
	TunnelIDs        []string    `json:"tunnelIDs"`
	Domains          []string    `json:"domains"`
	GeoIP            []string    `json:"geoIP"`
	Sets             []string    `json:"sets"`
	Applications     []string    `json:"applications"`
	Services         []string    `json:"services"`
}

type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

type RuleAction struct {
	Type   string `json:"type"`
	Target string `json:"target"`
	NAT    bool   `json:"nat"`
	Log    bool   `json:"log"`
	Mark   int    `json:"mark"`
	Table  int    `json:"table"`
}

type SecurityConfig struct {
	NAT              bool             `json:"nat"`
	Firewall         bool             `json:"firewall"`
	AllowEstablished bool             `json:"allowEstablished"`
	ManagementPorts  []int            `json:"managementPorts"`
	PortForwards     []PortForward    `json:"portForwards"`
	Antivirus        AntivirusConfig  `json:"antivirus"`
	IPS              IPSConfig        `json:"ips"`
	DNSFiltering     DNSFilteringConf `json:"dnsFiltering"`
}

type ServicesConfig struct {
	DHCPServer DHCPServiceConfig `json:"dhcpServer"`
	DHCPClient DHCPClientConfig  `json:"dhcpClient"`
	DNSServer  DNSServiceConfig  `json:"dnsServer"`
	DNSClient  DNSClientConfig   `json:"dnsClient"`
	NTPServer  NTPServiceConfig  `json:"ntpServer"`
	NTPClient  NTPClientConfig   `json:"ntpClient"`
	MPLS       MPLSConfig        `json:"mpls"`
}

type DHCPServiceConfig struct {
	Enabled bool     `json:"enabled"`
	Engine  string   `json:"engine"`
	Listen  []string `json:"listen"`
}

type DHCPClientConfig struct {
	Enabled    bool     `json:"enabled"`
	Interfaces []string `json:"interfaces"`
}

type DNSServiceConfig struct {
	Enabled      bool     `json:"enabled"`
	Engine       string   `json:"engine"`
	Listen       []string `json:"listen"`
	Forwarders   []string `json:"forwarders"`
	LocalDomains []string `json:"localDomains"`
}

type DNSClientConfig struct {
	Enabled   bool     `json:"enabled"`
	Resolvers []string `json:"resolvers"`
	Search    []string `json:"search"`
}

type NTPServiceConfig struct {
	Enabled bool     `json:"enabled"`
	Engine  string   `json:"engine"`
	Listen  []string `json:"listen"`
}

type NTPClientConfig struct {
	Enabled bool     `json:"enabled"`
	Servers []string `json:"servers"`
}

type MPLSConfig struct {
	Enabled    bool     `json:"enabled"`
	Interfaces []string `json:"interfaces"`
	LDP        bool     `json:"ldp"`
	VRF        string   `json:"vrf"`
}

type PortForward struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Enabled      bool     `json:"enabled"`
	InputIface   string   `json:"inputIface"`
	Protocols    []string `json:"protocols"`
	ExternalPort int      `json:"externalPort"`
	InternalIP   string   `json:"internalIp"`
	InternalPort int      `json:"internalPort"`
	SourceCIDRs  []string `json:"sourceCIDRs"`
	Log          bool     `json:"log"`
}

type AntivirusConfig struct {
	Enabled       bool     `json:"enabled"`
	Mode          string   `json:"mode"`
	Interfaces    []string `json:"interfaces"`
	MaxFileSizeMB int      `json:"maxFileSizeMB"`
	QuarantineDir string   `json:"quarantineDir"`
}

type IPSConfig struct {
	Enabled    bool     `json:"enabled"`
	Engine     string   `json:"engine"`
	Mode       string   `json:"mode"`
	Interfaces []string `json:"interfaces"`
	NFQueue    int      `json:"nfqueue"`
}

type DNSFilteringConf struct {
	Enabled    bool     `json:"enabled"`
	Upstream   []string `json:"upstream"`
	Blocklists []string `json:"blocklists"`
}

func Default() Config {
	return Config{
		Version: CurrentVersion,
		Host: HostConfig{
			Hostname:        "las",
			ManagementCIDRs: []string{"192.168.88.0/24"},
			EnableIPForward: true,
			ConntrackMax:    262144,
		},
		UI: UIConfig{
			Listen:        "127.0.0.1:8088",
			AdminUsername: "admin",
		},
		Interfaces: []Interface{
			{
				Name:       "enp1s0",
				Role:       "wan",
				Enabled:    true,
				Addresses:  []string{"dhcp"},
				DNS:        []string{"1.1.1.1", "9.9.9.9"},
				MTU:        1500,
				Masquerade: true,
			},
			{
				Name:      "enp2s0",
				Role:      "lan",
				Enabled:   true,
				Addresses: []string{"192.168.88.1/24"},
				MTU:       1500,
			},
		},
		Routing: RoutingConfig{
			DefaultPolicy: "wan",
			Sets:          []RouteSet{},
			WANGroups:     []WANGroup{},
			StaticRoutes:  []StaticRoute{},
			Rules:         []RouteRule{},
		},
		Services: ServicesConfig{
			DHCPServer: DHCPServiceConfig{Engine: "dnsmasq"},
			DHCPClient: DHCPClientConfig{Enabled: true, Interfaces: []string{"enp1s0"}},
			DNSServer: DNSServiceConfig{
				Engine:     "dnsmasq",
				Listen:     []string{"enp2s0"},
				Forwarders: []string{"1.1.1.1", "9.9.9.9"},
			},
			DNSClient: DNSClientConfig{
				Enabled:   true,
				Resolvers: []string{"1.1.1.1", "9.9.9.9"},
			},
			NTPServer: NTPServiceConfig{Engine: "chrony", Listen: []string{"enp2s0"}},
			NTPClient: NTPClientConfig{Enabled: true, Servers: []string{"pool.ntp.org"}},
		},
		Security: SecurityConfig{
			NAT:              true,
			Firewall:         true,
			AllowEstablished: true,
			ManagementPorts:  []int{22, 8088},
			PortForwards:     []PortForward{},
			Antivirus: AntivirusConfig{
				Mode:          "icap",
				MaxFileSizeMB: 100,
				QuarantineDir: "/var/lib/las/quarantine",
			},
			IPS: IPSConfig{
				Engine: "suricata",
				Mode:   "af-packet",
			},
			DNSFiltering: DNSFilteringConf{
				Upstream: []string{"1.1.1.1", "9.9.9.9"},
			},
		},
	}
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Save(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".router-*.json")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}

func Init(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return Save(path, Default())
}
