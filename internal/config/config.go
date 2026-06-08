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
	Platform   PlatformConfig `json:"platform"`
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
	OneToOneNAT      []OneToOneNAT    `json:"oneToOneNat"`
	Antivirus        AntivirusConfig  `json:"antivirus"`
	IPS              IPSConfig        `json:"ips"`
	DNSFiltering     DNSFilteringConf `json:"dnsFiltering"`
	ThreatFeeds      ThreatFeedConfig `json:"threatFeeds"`
	CaptivePortal    CaptivePortal    `json:"captivePortal"`
	RADIUS           RADIUSConfig     `json:"radius"`
	UPnP             UPnPConfig       `json:"upnp"`
}

type ServicesConfig struct {
	DHCPServer       DHCPServiceConfig `json:"dhcpServer"`
	DHCPClient       DHCPClientConfig  `json:"dhcpClient"`
	DNSServer        DNSServiceConfig  `json:"dnsServer"`
	DNSClient        DNSClientConfig   `json:"dnsClient"`
	NTPServer        NTPServiceConfig  `json:"ntpServer"`
	NTPClient        NTPClientConfig   `json:"ntpClient"`
	CertificateStore CertificateStore  `json:"certificateStore"`
	MPLS             MPLSConfig        `json:"mpls"`
}

type DHCPServiceConfig struct {
	Enabled       bool              `json:"enabled"`
	Engine        string            `json:"engine"`
	Listen        []string          `json:"listen"`
	Authoritative bool              `json:"authoritative"`
	LeaseFile     string            `json:"leaseFile"`
	StaticLeases  []DHCPStaticLease `json:"staticLeases"`
	Options       []DHCPOption      `json:"options"`
}

type DHCPClientConfig struct {
	Enabled    bool     `json:"enabled"`
	Interfaces []string `json:"interfaces"`
}

type DHCPStaticLease struct {
	Hostname string `json:"hostname"`
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Lease    string `json:"lease"`
}

type DHCPOption struct {
	Tag   string `json:"tag"`
	Code  string `json:"code"`
	Value string `json:"value"`
}

type DNSServiceConfig struct {
	Enabled               bool             `json:"enabled"`
	Engine                string           `json:"engine"`
	Listen                []string         `json:"listen"`
	ListenAddresses       []string         `json:"listenAddresses"`
	Forwarders            []string         `json:"forwarders"`
	LocalDomains          []string         `json:"localDomains"`
	ConditionalForwarders []DNSForwardZone `json:"conditionalForwarders"`
	Records               []DNSRecord      `json:"records"`
	AddressOverrides      []DNSOverride    `json:"addressOverrides"`
	CacheSize             int              `json:"cacheSize"`
	BindInterfaces        bool             `json:"bindInterfaces"`
	DNSSEC                bool             `json:"dnssec"`
	RebindProtection      bool             `json:"rebindProtection"`
	StrictOrder           bool             `json:"strictOrder"`
}

type DNSClientConfig struct {
	Enabled            bool     `json:"enabled"`
	Resolvers          []string `json:"resolvers"`
	FallbackResolvers  []string `json:"fallbackResolvers"`
	Search             []string `json:"search"`
	UseSystemdResolved bool     `json:"useSystemdResolved"`
	WriteResolvConf    bool     `json:"writeResolvConf"`
	DNSOverTLS         bool     `json:"dnsOverTLS"`
	DNSSEC             string   `json:"dnssec"`
}

type NTPServiceConfig struct {
	Enabled      bool      `json:"enabled"`
	Engine       string    `json:"engine"`
	Listen       []string  `json:"listen"`
	AllowCIDRs   []string  `json:"allowCidrs"`
	LocalStratum int       `json:"localStratum"`
	NTS          NTSConfig `json:"nts"`
}

type NTPClientConfig struct {
	Enabled         bool     `json:"enabled"`
	Servers         []string `json:"servers"`
	Pools           []string `json:"pools"`
	Peers           []string `json:"peers"`
	FallbackServers []string `json:"fallbackServers"`
	NTS             bool     `json:"nts"`
	Makestep        bool     `json:"makestep"`
}

type MPLSConfig struct {
	Enabled    bool     `json:"enabled"`
	Interfaces []string `json:"interfaces"`
	LDP        bool     `json:"ldp"`
	VRF        string   `json:"vrf"`
}

type DNSForwardZone struct {
	Domain    string   `json:"domain"`
	Upstreams []string `json:"upstreams"`
}

type DNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

type DNSOverride struct {
	Domain  string `json:"domain"`
	Address string `json:"address"`
}

type NTSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

type CertificateStore struct {
	Enabled      bool                   `json:"enabled"`
	Directory    string                 `json:"directory"`
	TrustStore   string                 `json:"trustStore"`
	Authorities  []CertificateAuthority `json:"authorities"`
	Certificates []ManagedCertificate   `json:"certificates"`
	LetsEncrypt  ACMEConfig             `json:"letsEncrypt"`
}

type CertificateAuthority struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	SourceFile string `json:"sourceFile"`
	PEM        string `json:"pem"`
	Install    bool   `json:"install"`
}

type ManagedCertificate struct {
	ID            string   `json:"id"`
	Domains       []string `json:"domains"`
	CertFile      string   `json:"certFile"`
	KeyFile       string   `json:"keyFile"`
	ChainFile     string   `json:"chainFile"`
	FullChainFile string   `json:"fullChainFile"`
	OwnerService  string   `json:"ownerService"`
	RenewHook     string   `json:"renewHook"`
}

type ACMEConfig struct {
	Enabled      bool              `json:"enabled"`
	Engine       string            `json:"engine"`
	Email        string            `json:"email"`
	DirectoryURL string            `json:"directoryUrl"`
	Staging      bool              `json:"staging"`
	Webroot      string            `json:"webroot"`
	RenewTimer   bool              `json:"renewTimer"`
	Certificates []ACMECertificate `json:"certificates"`
}

type ACMECertificate struct {
	ID          string   `json:"id"`
	Domains     []string `json:"domains"`
	Method      string   `json:"method"`
	Webroot     string   `json:"webroot"`
	DNSProvider string   `json:"dnsProvider"`
	KeyType     string   `json:"keyType"`
	DeployHook  string   `json:"deployHook"`
	Staging     bool     `json:"staging"`
}

type PlatformConfig struct {
	L2         L2Config         `json:"l2"`
	Routing    DynamicRouting   `json:"dynamicRouting"`
	QoS        QoSConfig        `json:"qos"`
	Monitor    MonitoringConfig `json:"monitoring"`
	Automation AutomationConfig `json:"automation"`
	Access     AccessConfig     `json:"access"`
}

type L2Config struct {
	VLANs   []VLAN   `json:"vlans"`
	Bridges []Bridge `json:"bridges"`
	Bonds   []Bond   `json:"bonds"`
	VRRP    []VRRP   `json:"vrrp"`
}

type VLAN struct {
	Name   string   `json:"name"`
	Parent string   `json:"parent"`
	ID     int      `json:"id"`
	MTU    int      `json:"mtu"`
	Role   string   `json:"role"`
	IPs    []string `json:"ips"`
}

type Bridge struct {
	Name        string   `json:"name"`
	Members     []string `json:"members"`
	STP         bool     `json:"stp"`
	VLANAware   bool     `json:"vlanAware"`
	VLANs       []int    `json:"vlans"`
	MTU         int      `json:"mtu"`
	Description string   `json:"description"`
}

type Bond struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
	Mode    string   `json:"mode"`
	LACP    string   `json:"lacp"`
	MTU     int      `json:"mtu"`
}

type VRRP struct {
	ID        string   `json:"id"`
	Interface string   `json:"interface"`
	VRID      int      `json:"vrid"`
	Priority  int      `json:"priority"`
	VIPs      []string `json:"vips"`
	Preempt   bool     `json:"preempt"`
}

type DynamicRouting struct {
	VRFs      []VRF      `json:"vrfs"`
	BGP       BGPConfig  `json:"bgp"`
	OSPF      OSPFConfig `json:"ospf"`
	RIP       RIPConfig  `json:"rip"`
	BFD       BFDConfig  `json:"bfd"`
	RouteMaps []RouteMap `json:"routeMaps"`
}

type VRF struct {
	Name       string   `json:"name"`
	Table      int      `json:"table"`
	Interfaces []string `json:"interfaces"`
}

type BGPConfig struct {
	Enabled  bool          `json:"enabled"`
	ASN      int           `json:"asn"`
	RouterID string        `json:"routerId"`
	Networks []string      `json:"networks"`
	Peers    []RoutingPeer `json:"peers"`
}

type OSPFConfig struct {
	Enabled  bool     `json:"enabled"`
	RouterID string   `json:"routerId"`
	Networks []string `json:"networks"`
}

type RIPConfig struct {
	Enabled  bool     `json:"enabled"`
	Networks []string `json:"networks"`
}

type BFDConfig struct {
	Enabled bool          `json:"enabled"`
	Peers   []RoutingPeer `json:"peers"`
}

type RoutingPeer struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	RemoteASN   int    `json:"remoteAsn"`
	Password    string `json:"password"`
	Interface   string `json:"interface"`
	Multihop    int    `json:"multihop"`
	RouteMapIn  string `json:"routeMapIn"`
	RouteMapOut string `json:"routeMapOut"`
}

type RouteMap struct {
	Name     string   `json:"name"`
	Sequence int      `json:"sequence"`
	Action   string   `json:"action"`
	Matches  []string `json:"matches"`
	Sets     []string `json:"sets"`
}

type QoSConfig struct {
	Enabled bool       `json:"enabled"`
	Queues  []QoSQueue `json:"queues"`
}

type QoSQueue struct {
	ID        string `json:"id"`
	Interface string `json:"interface"`
	Kind      string `json:"kind"`
	Rate      string `json:"rate"`
	Ceil      string `json:"ceil"`
	Priority  int    `json:"priority"`
	MatchMark int    `json:"matchMark"`
}

type MonitoringConfig struct {
	SNMP          SNMPConfig          `json:"snmp"`
	NetFlow       NetFlowConfig       `json:"netflow"`
	TrafficGraphs TrafficGraphsConfig `json:"trafficGraphs"`
}

type SNMPConfig struct {
	Enabled   bool   `json:"enabled"`
	Community string `json:"community"`
	Listen    string `json:"listen"`
	Location  string `json:"location"`
	Contact   string `json:"contact"`
}

type NetFlowConfig struct {
	Enabled    bool     `json:"enabled"`
	Engine     string   `json:"engine"`
	Collector  string   `json:"collector"`
	Port       int      `json:"port"`
	Interfaces []string `json:"interfaces"`
}

type TrafficGraphsConfig struct {
	Enabled bool   `json:"enabled"`
	Engine  string `json:"engine"`
	Listen  string `json:"listen"`
}

type AutomationConfig struct {
	AuditLog         AuditLogConfig   `json:"auditLog"`
	RollbackWatchdog RollbackWatchdog `json:"rollbackWatchdog"`
	Scheduler        []ScheduledJob   `json:"scheduler"`
	Backup           BackupConfig     `json:"backup"`
}

type AuditLogConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

type RollbackWatchdog struct {
	Enabled      bool   `json:"enabled"`
	ProbeTarget  string `json:"probeTarget"`
	Timeout      string `json:"timeout"`
	RecoveryPath string `json:"recoveryPath"`
}

type ScheduledJob struct {
	ID       string `json:"id"`
	Enabled  bool   `json:"enabled"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
}

type BackupConfig struct {
	Enabled     bool   `json:"enabled"`
	Schedule    string `json:"schedule"`
	Destination string `json:"destination"`
	Encrypt     bool   `json:"encrypt"`
}

type AccessConfig struct {
	AuthEnabled bool   `json:"authEnabled"`
	SessionTTL  string `json:"sessionTtl"`
	Users       []User `json:"users"`
	Roles       []Role `json:"roles"`
}

type User struct {
	Username     string   `json:"username"`
	PasswordHash string   `json:"passwordHash"`
	Roles        []string `json:"roles"`
	Disabled     bool     `json:"disabled"`
}

type Role struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
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

type OneToOneNAT struct {
	ID           string   `json:"id"`
	Enabled      bool     `json:"enabled"`
	InternalCIDR string   `json:"internalCidr"`
	ExternalCIDR string   `json:"externalCidr"`
	Interfaces   []string `json:"interfaces"`
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

type ThreatFeedConfig struct {
	Enabled    bool     `json:"enabled"`
	SourceURLs []string `json:"sourceUrls"`
	Refresh    string   `json:"refresh"`
	Action     string   `json:"action"`
}

type CaptivePortal struct {
	Enabled    bool     `json:"enabled"`
	Engine     string   `json:"engine"`
	Interfaces []string `json:"interfaces"`
	LoginURL   string   `json:"loginUrl"`
	RADIUS     bool     `json:"radius"`
}

type RADIUSConfig struct {
	Enabled bool     `json:"enabled"`
	Servers []string `json:"servers"`
	Secret  string   `json:"secret"`
	NASID   string   `json:"nasId"`
}

type UPnPConfig struct {
	Enabled        bool     `json:"enabled"`
	InternalIfaces []string `json:"internalIfaces"`
	ExternalIface  string   `json:"externalIface"`
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
				Engine:           "dnsmasq",
				Listen:           []string{"enp2s0"},
				Forwarders:       []string{"1.1.1.1", "9.9.9.9"},
				CacheSize:        10000,
				BindInterfaces:   true,
				RebindProtection: true,
			},
			DNSClient: DNSClientConfig{
				Enabled:            true,
				Resolvers:          []string{"1.1.1.1", "9.9.9.9"},
				FallbackResolvers:  []string{"8.8.8.8"},
				UseSystemdResolved: true,
			},
			NTPServer: NTPServiceConfig{Engine: "chrony", Listen: []string{"enp2s0"}, LocalStratum: 10},
			NTPClient: NTPClientConfig{Enabled: true, Pools: []string{"pool.ntp.org"}, Makestep: true},
			CertificateStore: CertificateStore{
				Directory:  "/etc/las/certs",
				TrustStore: "/usr/local/share/ca-certificates",
				LetsEncrypt: ACMEConfig{
					Engine:     "certbot",
					Webroot:    "/var/www/letsencrypt",
					RenewTimer: true,
				},
			},
		},
		Platform: PlatformConfig{
			Access: AccessConfig{
				SessionTTL: "12h",
				Roles: []Role{
					{Name: "admin", Permissions: []string{"*"}},
					{Name: "viewer", Permissions: []string{"read:*"}},
				},
			},
			Automation: AutomationConfig{
				AuditLog: AuditLogConfig{Enabled: true, Path: "/var/log/las/audit.log"},
			},
		},
		Security: SecurityConfig{
			NAT:              true,
			Firewall:         true,
			AllowEstablished: true,
			ManagementPorts:  []int{22, 8088},
			PortForwards:     []PortForward{},
			OneToOneNAT:      []OneToOneNAT{},
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
