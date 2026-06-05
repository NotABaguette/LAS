const state = {
  config: null,
  status: null,
  tab: "dashboard",
};

const $ = (selector) => document.querySelector(selector);
const content = $("#content");
const output = $("#output");
const notice = $("#notice");

const titles = {
  dashboard: "Dashboard",
  interfaces: "Interfaces",
  tunnels: "Tunnels",
  rules: "Policy Rules",
  services: "Services",
  security: "Security",
  diagnostics: "Diagnostics",
  raw: "Raw Config",
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `${response.status} ${response.statusText}`);
  }
  return data;
}

async function load() {
  const [config, status] = await Promise.all([
    api("/api/config"),
    api("/api/status").catch(() => null),
  ]);
  state.config = config;
  state.status = status;
  render();
  message("Configuration loaded.");
}

function render() {
  document.querySelectorAll(".nav-item").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === state.tab);
  });
  $("#page-title").textContent = titles[state.tab];

  const renderers = {
    dashboard: renderDashboard,
    interfaces: renderInterfaces,
    tunnels: renderTunnels,
    rules: renderRules,
    services: renderServices,
    security: renderSecurity,
    diagnostics: renderDiagnostics,
    raw: renderRaw,
  };
  content.innerHTML = "";
  content.append(renderers[state.tab]());
}

function renderDashboard() {
  const cfg = state.config;
  const root = el("div", "grid");
  root.append(
    metricCard("Interfaces", cfg.interfaces.length, `${enabledCount(cfg.interfaces)} enabled`),
    metricCard("Tunnels", cfg.tunnels.length, `${enabledCount(cfg.tunnels)} enabled`),
    metricCard("Rules", cfg.routing.rules.length, `${enabledCount(cfg.routing.rules)} enabled`),
  );

  const host = card("Host", "full");
  host.append(formGrid([
    textField("Hostname", cfg.host.hostname, (value) => cfg.host.hostname = value),
    textField("UI listen", cfg.ui.listen, (value) => cfg.ui.listen = value),
    listField("Management CIDRs", cfg.host.managementCIDRs, (value) => cfg.host.managementCIDRs = value),
    numberField("Conntrack max", cfg.host.conntrackMax, (value) => cfg.host.conntrackMax = value),
    checkboxField("Enable IP forwarding", cfg.host.enableIPForward, (value) => cfg.host.enableIPForward = value),
  ]));
  root.append(host);

  const services = card("Host Capabilities", "full");
  const table = el("div", "service-table");
  const commands = state.status?.commands || {};
  Object.entries(commands).forEach(([name, value]) => {
    table.append(serviceRow(name, value));
  });
  if (!Object.keys(commands).length) {
    table.append(el("p", "muted", "Status probe unavailable."));
  }
  services.append(table);
  root.append(services);

  return root;
}

function renderInterfaces() {
  const root = el("div", "grid");
  state.config.interfaces.forEach((iface, index) => {
    const item = card(iface.name || `Interface ${index + 1}`);
    item.append(formGrid([
      textField("Name", iface.name, (value) => iface.name = value),
      selectField("Role", iface.role, ["wan", "lan", "dmz", "mgmt", "tunnel"], (value) => iface.role = value),
      checkboxField("Enabled", iface.enabled, (value) => iface.enabled = value),
      checkboxField("Masquerade", iface.masquerade, (value) => iface.masquerade = value),
      listField("Addresses", iface.addresses, (value) => iface.addresses = value, "Use dhcp or CIDR values."),
      textField("Gateway", iface.gateway, (value) => iface.gateway = value),
      listField("DNS", iface.dns, (value) => iface.dns = value),
      numberField("MTU", iface.mtu, (value) => iface.mtu = value),
    ]));
    item.append(actions([
      ["Add DHCP server", () => {
        iface.dhcpServer = iface.dhcpServer || { rangeStart: "", rangeEnd: "", leaseTime: "12h", dns: [], domain: "lan" };
        render();
      }],
      ["Remove", () => removeAt(state.config.interfaces, index), "danger"],
    ]));
    if (iface.dhcpServer) {
      const dhcp = card("DHCP server", "full");
      dhcp.append(formGrid([
        textField("Range start", iface.dhcpServer.rangeStart, (value) => iface.dhcpServer.rangeStart = value),
        textField("Range end", iface.dhcpServer.rangeEnd, (value) => iface.dhcpServer.rangeEnd = value),
        textField("Lease time", iface.dhcpServer.leaseTime, (value) => iface.dhcpServer.leaseTime = value),
        listField("DNS", iface.dhcpServer.dns, (value) => iface.dhcpServer.dns = value),
        textField("Domain", iface.dhcpServer.domain, (value) => iface.dhcpServer.domain = value),
      ]));
      dhcp.append(actions([["Remove DHCP", () => { iface.dhcpServer = null; render(); }, "danger"]]));
      item.append(dhcp);
    }
    root.append(item);
  });
  root.append(addCard("Add interface", () => {
    state.config.interfaces.push({
      name: "enp0s0",
      role: "lan",
      enabled: true,
      addresses: ["192.168.10.1/24"],
      gateway: "",
      dns: [],
      mtu: 1500,
      masquerade: false,
    });
    render();
  }));
  return root;
}

function renderTunnels() {
  const root = el("div", "grid");
  state.config.tunnels.forEach((tunnel, index) => {
    const item = card(tunnel.name || tunnel.id || `Tunnel ${index + 1}`);
    item.append(formGrid([
      textField("ID", tunnel.id, (value) => tunnel.id = value),
      textField("Name", tunnel.name, (value) => tunnel.name = value),
      selectField("Type", tunnel.type, ["tun", "wireguard", "openvpn", "ipsec", "ipsec-vti", "vti", "l2tp", "l2tp-ipsec", "pptp", "sstp", "pppoe", "gre", "gretap", "eoip", "ipip", "sit", "6to4", "ip6gre", "ip6tnl", "erspan", "vxlan", "l2tpv3", "vless", "vmess", "vless-xhttp", "xhttp", "xray", "sing-box", "tailscale", "zerotier", "custom"], (value) => tunnel.type = value),
      selectField("Direction", tunnel.direction, ["client", "server", "peer"], (value) => tunnel.direction = value),
      checkboxField("Enabled", tunnel.enabled, (value) => tunnel.enabled = value),
      textField("Interface", tunnel.interfaceName, (value) => tunnel.interfaceName = value),
      textField("Remote endpoint", tunnel.remoteEndpoint, (value) => tunnel.remoteEndpoint = value),
      numberField("Fwmark", tunnel.mark, (value) => tunnel.mark = value),
      numberField("Routing table", tunnel.table, (value) => tunnel.table = value),
      numberField("MTU", tunnel.mtu, (value) => tunnel.mtu = value),
      listField("Local addresses", tunnel.localAddresses, (value) => tunnel.localAddresses = value),
      listField("DNS", tunnel.dns, (value) => tunnel.dns = value),
      kvField("Credentials", tunnel.credentials || {}, (value) => tunnel.credentials = value),
      kvField("Options", tunnel.options || {}, (value) => tunnel.options = value),
    ]));
    item.append(actions([["Remove", () => removeAt(state.config.tunnels, index), "danger"]]));
    root.append(item);
  });
  root.append(addCard("Add tunnel", () => {
    state.config.tunnels.push({
      id: `tun-${state.config.tunnels.length + 1}`,
      name: "New tunnel",
      type: "wireguard",
      direction: "client",
      enabled: false,
      interfaceName: `wg${state.config.tunnels.length}`,
      mark: 4096 + state.config.tunnels.length + 1,
      table: 100 + state.config.tunnels.length + 1,
      mtu: 1420,
      remoteEndpoint: "",
      localAddresses: [],
      dns: [],
      credentials: { configFile: "" },
      options: {},
    });
    render();
  }));
  return root;
}

function renderRules() {
  const root = el("div", "grid");
  state.config.routing.sets = state.config.routing.sets || [];
  state.config.routing.wanGroups = state.config.routing.wanGroups || [];
  const rules = state.config.routing.rules;
  rules.sort((a, b) => a.priority - b.priority);
  rules.forEach((rule, index) => {
    rule.match.sets = rule.match.sets || [];
    rule.match.applications = rule.match.applications || [];
    rule.match.services = rule.match.services || [];
    const item = card(rule.name || rule.id || `Rule ${index + 1}`, "full");
    item.append(formGrid([
      textField("ID", rule.id, (value) => rule.id = value),
      textField("Name", rule.name, (value) => rule.name = value),
      checkboxField("Enabled", rule.enabled, (value) => rule.enabled = value),
      numberField("Priority", rule.priority, (value) => rule.priority = value),
      textField("Input iface/link", rule.match.inputIface, (value) => rule.match.inputIface = value),
      textField("Output iface/link", rule.match.outputIface, (value) => rule.match.outputIface = value),
      listField("Source CIDRs", rule.match.sourceCIDRs, (value) => rule.match.sourceCIDRs = value),
      listField("Destination CIDRs", rule.match.destinationCIDRs, (value) => rule.match.destinationCIDRs = value),
      portsField("Source ports", rule.match.sourcePorts, (value) => rule.match.sourcePorts = value),
      portsField("Destination ports", rule.match.destinationPorts, (value) => rule.match.destinationPorts = value),
      listField("Protocols", rule.match.protocols, (value) => rule.match.protocols = value, "tcp, udp, icmp, icmpv6, gre, esp, ah"),
      listField("Tunnel match IDs", rule.match.tunnelIDs, (value) => rule.match.tunnelIDs = value),
      listField("Domains", rule.match.domains, (value) => rule.match.domains = value),
      listField("GeoIP", rule.match.geoIP, (value) => rule.match.geoIP = value),
      listField("Route sets", rule.match.sets, (value) => rule.match.sets = value, "Match destination IPs from route sets such as iran, telegram, whatsapp."),
      listField("Applications", rule.match.applications, (value) => rule.match.applications = value, "Labels for app-aware feed mapping."),
      listField("Services", rule.match.services, (value) => rule.match.services = value, "Labels for service-aware feed mapping."),
      selectField("Action", rule.action.type, ["direct", "interface", "tunnel", "wan-group", "load-balance", "blackhole", "reject", "scan", "mirror"], (value) => rule.action.type = value),
      textField("Target", rule.action.target, (value) => rule.action.target = value),
      checkboxField("NAT", rule.action.nat, (value) => rule.action.nat = value),
      checkboxField("Log", rule.action.log, (value) => rule.action.log = value),
      numberField("Mark override", rule.action.mark, (value) => rule.action.mark = value),
      numberField("Table override", rule.action.table, (value) => rule.action.table = value),
    ]));
    item.append(actions([
      ["Duplicate", () => {
        const clone = JSON.parse(JSON.stringify(rule));
        clone.id = `${rule.id}-copy`;
        clone.priority += 10;
        rules.splice(index + 1, 0, clone);
        render();
      }],
      ["Remove", () => removeAt(rules, index), "danger"],
    ]));
    root.append(item);
  });

  const sets = card("Geo / App / Service Route Sets", "full");
  state.config.routing.sets.forEach((routeSet, index) => {
    const row = el("div", "card full");
    row.append(formGrid([
      textField("ID", routeSet.id, (value) => routeSet.id = value),
      textField("Name", routeSet.name, (value) => routeSet.name = value),
      selectField("Type", routeSet.type, ["country", "application", "service", "custom"], (value) => routeSet.type = value),
      checkboxField("Enabled", routeSet.enabled, (value) => routeSet.enabled = value),
      textField("Description", routeSet.description, (value) => routeSet.description = value),
      listField("Countries", routeSet.countries, (value) => routeSet.countries = value, "ISO country codes, e.g. IR."),
      listField("Static CIDRs", routeSet.cidrs, (value) => routeSet.cidrs = value, "CIDRs rendered directly into nftables sets."),
      listField("Domains", routeSet.domains, (value) => routeSet.domains = value, "Domains that a feed generator can resolve into CIDRs."),
      listField("Source URLs", routeSet.sourceUrls, (value) => routeSet.sourceUrls = value, "Feed URLs for GeoIP/app/service CIDRs."),
      textField("Refresh", routeSet.refresh, (value) => routeSet.refresh = value, "Example: 24h"),
    ]));
    row.append(actions([["Remove set", () => removeAt(state.config.routing.sets, index), "danger"]]));
    sets.append(row);
  });
  sets.append(actions([["Add route set", () => {
    state.config.routing.sets.push({
      id: `set-${state.config.routing.sets.length + 1}`,
      name: "New route set",
      type: "custom",
      enabled: true,
      description: "",
      countries: [],
      cidrs: [],
      domains: [],
      sourceUrls: [],
      refresh: "24h",
    });
    render();
  }]]));
  root.append(sets);

  const wanGroups = card("WAN Load Balancing Groups", "full");
  state.config.routing.wanGroups.forEach((group, index) => {
    const row = el("div", "card full");
    row.append(formGrid([
      textField("ID", group.id, (value) => group.id = value),
      textField("Name", group.name, (value) => group.name = value),
      checkboxField("Enabled", group.enabled, (value) => group.enabled = value),
      selectField("Mode", group.mode, ["weighted-ecmp", "failover", "active-backup"], (value) => group.mode = value),
      numberField("Fwmark", group.mark, (value) => group.mark = value),
      numberField("Routing table", group.table, (value) => group.table = value),
      wanMembersField("Members", group.members, (value) => group.members = value),
    ]));
    row.append(actions([["Remove WAN group", () => removeAt(state.config.routing.wanGroups, index), "danger"]]));
    wanGroups.append(row);
  });
  wanGroups.append(actions([["Add WAN group", () => {
    state.config.routing.wanGroups.push({
      id: `wan-group-${state.config.routing.wanGroups.length + 1}`,
      name: "New WAN group",
      enabled: true,
      mode: "weighted-ecmp",
      mark: 8192 + state.config.routing.wanGroups.length + 1,
      table: 200 + state.config.routing.wanGroups.length + 1,
      members: [{ interface: "enp1s0", gateway: "", weight: 1, priority: 100, healthcheck: "1.1.1.1" }],
    });
    render();
  }]]));
  root.append(wanGroups);

  const staticRoutes = card("Static Routes", "full");
  state.config.routing.staticRoutes.forEach((route, index) => {
    const row = el("div", "card full");
    row.append(formGrid([
      textField("Destination", route.destination, (value) => route.destination = value),
      textField("Gateway", route.gateway, (value) => route.gateway = value),
      textField("Interface/link", route.interface, (value) => route.interface = value),
      numberField("Table", route.table, (value) => route.table = value),
      numberField("Metric", route.metric, (value) => route.metric = value),
    ]));
    row.append(actions([["Remove route", () => removeAt(state.config.routing.staticRoutes, index), "danger"]]));
    staticRoutes.append(row);
  });
  staticRoutes.append(actions([["Add static route", () => {
    state.config.routing.staticRoutes.push({ destination: "0.0.0.0/0", gateway: "", interface: "", table: 0, metric: 10 });
    render();
  }]]));
  root.append(staticRoutes);

  root.append(addCard("Add policy rule", () => {
    rules.push(newRule());
    render();
  }));
  return root;
}

function renderServices() {
  const services = state.config.services || (state.config.services = {});
  services.dhcpServer = services.dhcpServer || { enabled: false, engine: "dnsmasq", listen: [] };
  services.dhcpClient = services.dhcpClient || { enabled: true, interfaces: [] };
  services.dnsServer = services.dnsServer || { enabled: false, engine: "dnsmasq", listen: [], forwarders: [], localDomains: [] };
  services.dnsClient = services.dnsClient || { enabled: true, resolvers: [], search: [] };
  services.ntpServer = services.ntpServer || { enabled: false, engine: "chrony", listen: [] };
  services.ntpClient = services.ntpClient || { enabled: true, servers: [] };
  services.mpls = services.mpls || { enabled: false, interfaces: [], ldp: false, vrf: "" };

  const root = el("div", "grid");
  const dhcp = card("DHCP", "full");
  dhcp.append(formGrid([
    checkboxField("DHCP server enabled", services.dhcpServer.enabled, (value) => services.dhcpServer.enabled = value),
    selectField("DHCP server engine", services.dhcpServer.engine, ["dnsmasq", "kea"], (value) => services.dhcpServer.engine = value),
    listField("DHCP server listen links", services.dhcpServer.listen, (value) => services.dhcpServer.listen = value),
    checkboxField("DHCP client enabled", services.dhcpClient.enabled, (value) => services.dhcpClient.enabled = value),
    listField("DHCP client interfaces", services.dhcpClient.interfaces, (value) => services.dhcpClient.interfaces = value),
  ]));
  root.append(dhcp);

  const dns = card("DNS", "full");
  dns.append(formGrid([
    checkboxField("DNS server enabled", services.dnsServer.enabled, (value) => services.dnsServer.enabled = value),
    selectField("DNS server engine", services.dnsServer.engine, ["dnsmasq", "unbound", "bind"], (value) => services.dnsServer.engine = value),
    listField("DNS listen links", services.dnsServer.listen, (value) => services.dnsServer.listen = value),
    listField("DNS forwarders", services.dnsServer.forwarders, (value) => services.dnsServer.forwarders = value),
    listField("Local domains", services.dnsServer.localDomains, (value) => services.dnsServer.localDomains = value),
    checkboxField("DNS client enabled", services.dnsClient.enabled, (value) => services.dnsClient.enabled = value),
    listField("Client resolvers", services.dnsClient.resolvers, (value) => services.dnsClient.resolvers = value),
    listField("Search domains", services.dnsClient.search, (value) => services.dnsClient.search = value),
  ]));
  root.append(dns);

  const ntp = card("NTP", "full");
  ntp.append(formGrid([
    checkboxField("NTP server enabled", services.ntpServer.enabled, (value) => services.ntpServer.enabled = value),
    selectField("NTP engine", services.ntpServer.engine, ["chrony", "ntpd"], (value) => services.ntpServer.engine = value),
    listField("NTP server listen links", services.ntpServer.listen, (value) => services.ntpServer.listen = value),
    checkboxField("NTP client enabled", services.ntpClient.enabled, (value) => services.ntpClient.enabled = value),
    listField("NTP upstream servers", services.ntpClient.servers, (value) => services.ntpClient.servers = value),
  ]));
  root.append(ntp);

  const mpls = card("MPLS", "full");
  mpls.append(formGrid([
    checkboxField("MPLS enabled", services.mpls.enabled, (value) => services.mpls.enabled = value),
    listField("MPLS links", services.mpls.interfaces, (value) => services.mpls.interfaces = value),
    checkboxField("LDP enabled", services.mpls.ldp, (value) => services.mpls.ldp = value),
    textField("VRF", services.mpls.vrf, (value) => services.mpls.vrf = value),
  ]));
  root.append(mpls);
  return root;
}

function renderSecurity() {
  const sec = state.config.security;
  const root = el("div", "grid");
  sec.portForwards = sec.portForwards || [];

  const base = card("Firewall and NAT", "full");
  base.append(formGrid([
    checkboxField("Enable NAT", sec.nat, (value) => sec.nat = value),
    checkboxField("Enable firewall", sec.firewall, (value) => sec.firewall = value),
    checkboxField("Allow established", sec.allowEstablished, (value) => sec.allowEstablished = value),
    listField("Management ports", sec.managementPorts, (value) => sec.managementPorts = value.map(Number).filter(Boolean)),
  ]));
  root.append(base);

  const forwards = card("Port Forwarding", "full");
  sec.portForwards.forEach((forward, index) => {
    const row = el("div", "card full");
    row.append(formGrid([
      textField("ID", forward.id, (value) => forward.id = value),
      textField("Name", forward.name, (value) => forward.name = value),
      checkboxField("Enabled", forward.enabled, (value) => forward.enabled = value),
      textField("Input iface", forward.inputIface, (value) => forward.inputIface = value),
      listField("Protocols", forward.protocols, (value) => forward.protocols = value, "tcp and/or udp"),
      numberField("External port", forward.externalPort, (value) => forward.externalPort = value),
      textField("Internal IP", forward.internalIp, (value) => forward.internalIp = value),
      numberField("Internal port", forward.internalPort, (value) => forward.internalPort = value),
      listField("Allowed source CIDRs", forward.sourceCIDRs, (value) => forward.sourceCIDRs = value),
      checkboxField("Log", forward.log, (value) => forward.log = value),
    ]));
    row.append(actions([["Remove port forward", () => removeAt(sec.portForwards, index), "danger"]]));
    forwards.append(row);
  });
  forwards.append(actions([["Add port forward", () => {
    sec.portForwards.push({
      id: `pf-${sec.portForwards.length + 1}`,
      name: "New port forward",
      enabled: true,
      inputIface: "enp1s0",
      protocols: ["tcp"],
      externalPort: 443,
      internalIp: "192.168.88.10",
      internalPort: 443,
      sourceCIDRs: [],
      log: true,
    });
    render();
  }]]));
  root.append(forwards);

  const ips = card("IPS", "third");
  ips.append(formGrid([
    checkboxField("Enabled", sec.ips.enabled, (value) => sec.ips.enabled = value),
    selectField("Engine", sec.ips.engine, ["suricata"], (value) => sec.ips.engine = value),
    selectField("Mode", sec.ips.mode, ["af-packet", "nfqueue"], (value) => sec.ips.mode = value),
    listField("Interfaces", sec.ips.interfaces, (value) => sec.ips.interfaces = value),
    numberField("NFQueue", sec.ips.nfqueue, (value) => sec.ips.nfqueue = value),
  ]));
  root.append(ips);

  const av = card("Antivirus", "third");
  av.append(formGrid([
    checkboxField("Enabled", sec.antivirus.enabled, (value) => sec.antivirus.enabled = value),
    selectField("Mode", sec.antivirus.mode, ["icap", "proxy", "manual"], (value) => sec.antivirus.mode = value),
    listField("Interfaces", sec.antivirus.interfaces, (value) => sec.antivirus.interfaces = value),
    numberField("Max file MB", sec.antivirus.maxFileSizeMB, (value) => sec.antivirus.maxFileSizeMB = value),
    textField("Quarantine dir", sec.antivirus.quarantineDir, (value) => sec.antivirus.quarantineDir = value),
  ]));
  root.append(av);

  const dns = card("DNS Filtering", "third");
  dns.append(formGrid([
    checkboxField("Enabled", sec.dnsFiltering.enabled, (value) => sec.dnsFiltering.enabled = value),
    listField("Upstream", sec.dnsFiltering.upstream, (value) => sec.dnsFiltering.upstream = value),
    listField("Blocklists", sec.dnsFiltering.blocklists, (value) => sec.dnsFiltering.blocklists = value),
  ]));
  root.append(dns);

  return root;
}

function renderDiagnostics() {
  const root = el("div", "grid");
  const item = card("Network Diagnostics", "full");
  const tool = selectField("Tool", "ping", ["ping", "traceroute", "curl-head", "dig", "route"], () => {});
  const target = textField("Target", "1.1.1.1", () => {}, "IP, hostname, or http(s) URL for curl-head.");
  const count = numberField("Ping count", 4, () => {});
  const form = formGrid([tool, target, count]);
  const button = el("button", "primary", "Run diagnostic");
  button.type = "button";
  button.addEventListener("click", async () => {
    const request = {
      tool: tool.querySelector("select").value,
      target: target.querySelector("input").value,
      count: Number(count.querySelector("input").value || 4),
    };
    try {
      const result = await api("/api/diagnostics", {
        method: "POST",
        body: JSON.stringify(request),
      });
      output.textContent = JSON.stringify(result, null, 2);
      message("Diagnostic completed.");
    } catch (error) {
      message(error.message, true);
    }
  });
  item.append(form, actions([["Run diagnostic", () => button.click()]]));
  root.append(item);
  return root;
}

function renderRaw() {
  const root = el("div", "grid");
  const item = card("Raw JSON", "full");
  const textarea = el("textarea", "raw-editor");
  textarea.value = JSON.stringify(state.config, null, 2);
  item.append(textarea);
  item.append(actions([
    ["Load JSON into editor", () => {
      try {
        const next = JSON.parse(textarea.value);
        state.config = next;
        message("Raw JSON loaded into the UI state. Save to persist it.");
        render();
      } catch (error) {
        message(error.message, true);
      }
    }],
    ["Format", () => {
      try {
        textarea.value = JSON.stringify(JSON.parse(textarea.value), null, 2);
      } catch (error) {
        message(error.message, true);
      }
    }],
  ]));
  root.append(item);
  return root;
}

function metricCard(title, value, detail) {
  const item = card(title, "third");
  item.append(el("div", "metric", String(value)));
  item.append(el("p", "muted", detail));
  return item;
}

function card(title, extra = "") {
  const item = el("article", `card ${extra}`.trim());
  item.append(el("h3", "", title));
  return item;
}

function addCard(title, onClick) {
  const item = card(title);
  item.append(el("p", "muted", "Create a new entry with safe defaults, then customize it."));
  item.append(actions([[title, onClick]]));
  return item;
}

function formGrid(fields) {
  const root = el("div", "form-grid");
  fields.forEach((field) => root.append(field));
  return root;
}

function textField(label, value, onChange, hint = "") {
  return inputField(label, value ?? "", "text", (event) => onChange(event.target.value), hint);
}

function numberField(label, value, onChange) {
  return inputField(label, value ?? 0, "number", (event) => onChange(Number(event.target.value || 0)));
}

function inputField(labelText, value, type, onInput, hint = "") {
  const wrap = fieldWrap(labelText, hint);
  const input = el("input");
  input.type = type;
  input.value = value;
  input.addEventListener("input", onInput);
  wrap.append(input);
  return wrap;
}

function checkboxField(labelText, value, onChange) {
  const wrap = el("label", "switch-row");
  const input = el("input");
  input.type = "checkbox";
  input.checked = Boolean(value);
  input.addEventListener("change", (event) => onChange(event.target.checked));
  wrap.append(input, document.createTextNode(labelText));
  return wrap;
}

function selectField(labelText, value, options, onChange) {
  const wrap = fieldWrap(labelText);
  const select = el("select");
  options.forEach((option) => {
    const node = el("option");
    node.value = option;
    node.textContent = option;
    select.append(node);
  });
  select.value = value || options[0];
  select.addEventListener("change", (event) => onChange(event.target.value));
  wrap.append(select);
  return wrap;
}

function listField(labelText, value, onChange, hint = "Comma or newline separated.") {
  const wrap = fieldWrap(labelText, hint);
  const textarea = el("textarea");
  textarea.value = (value || []).join("\n");
  textarea.addEventListener("input", (event) => onChange(parseList(event.target.value)));
  wrap.append(textarea);
  return wrap;
}

function portsField(labelText, value, onChange) {
  const wrap = fieldWrap(labelText, "Use 443 or 1000-2000, comma/newline separated.");
  const input = el("textarea");
  input.value = formatPorts(value || []);
  input.addEventListener("input", (event) => onChange(parsePorts(event.target.value)));
  wrap.append(input);
  return wrap;
}

function wanMembersField(labelText, value, onChange) {
  const wrap = fieldWrap(labelText, "One per line: iface,gateway,weight,priority,healthcheck");
  wrap.classList.add("full");
  const input = el("textarea");
  input.value = formatWANMembers(value || []);
  input.addEventListener("input", (event) => onChange(parseWANMembers(event.target.value)));
  wrap.append(input);
  return wrap;
}

function kvField(labelText, value, onChange) {
  const wrap = fieldWrap(labelText, "key=value per line.");
  wrap.classList.add("full");
  const textarea = el("textarea");
  textarea.value = Object.entries(value || {}).map(([key, val]) => `${key}=${val}`).join("\n");
  textarea.addEventListener("input", (event) => onChange(parseKV(event.target.value)));
  wrap.append(textarea);
  return wrap;
}

function fieldWrap(labelText, hint = "") {
  const wrap = el("label", "field");
  wrap.append(el("span", "", labelText));
  if (hint) {
    wrap.append(el("small", "muted", hint));
  }
  return wrap;
}

function actions(items) {
  const root = el("div", "card-actions");
  items.forEach(([label, onClick, kind]) => {
    const button = el("button", kind === "danger" ? "danger" : "ghost", label);
    button.type = "button";
    button.addEventListener("click", onClick);
    root.append(button);
  });
  return root;
}

function serviceRow(name, value) {
  const row = el("div", "service-row");
  const stateClass = value === "missing" ? "bad" : value.includes("inactive") || value.includes("failed") ? "warn" : "";
  row.append(el("span", "", name), el("span", `badge ${stateClass}`.trim(), value));
  return row;
}

function enabledCount(items) {
  return items.filter((item) => item.enabled).length;
}

function removeAt(items, index) {
  items.splice(index, 1);
  render();
}

function newRule() {
  const priority = 100 + state.config.routing.rules.length * 10;
  return {
    id: `rule-${priority}`,
    name: "New policy rule",
    enabled: true,
    priority,
    match: {
      inputIface: "",
      outputIface: "",
      sourceCIDRs: [],
      destinationCIDRs: [],
      sourcePorts: [],
      destinationPorts: [],
      protocols: [],
      tunnelIDs: [],
      domains: [],
      geoIP: [],
      sets: [],
      applications: [],
      services: [],
    },
    action: {
      type: "direct",
      target: "",
      nat: false,
      log: false,
      mark: 0,
      table: 0,
    },
  };
}

function parseList(value) {
  return value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);
}

function parsePorts(value) {
  return parseList(value).map((item) => {
    const [from, to] = item.split("-").map((part) => Number(part.trim()));
    return { from, to: to || from };
  }).filter((item) => item.from > 0 && item.to > 0);
}

function formatPorts(value) {
  return value.map((range) => range.from === range.to ? `${range.from}` : `${range.from}-${range.to}`).join("\n");
}

function parseWANMembers(value) {
  return value.split("\n").map((line) => {
    const [iface, gateway = "", weight = "1", priority = "100", healthcheck = ""] = line.split(",").map((part) => part.trim());
    return {
      interface: iface,
      gateway,
      weight: Number(weight || 1),
      priority: Number(priority || 100),
      healthcheck,
    };
  }).filter((member) => member.interface);
}

function formatWANMembers(value) {
  return value.map((member) => [
    member.interface || "",
    member.gateway || "",
    member.weight || 1,
    member.priority || 100,
    member.healthcheck || "",
  ].join(",")).join("\n");
}

function parseKV(value) {
  return value.split("\n").reduce((acc, line) => {
    const trimmed = line.trim();
    if (!trimmed) return acc;
    const index = trimmed.indexOf("=");
    if (index === -1) {
      acc[trimmed] = "";
      return acc;
    }
    acc[trimmed.slice(0, index).trim()] = trimmed.slice(index + 1).trim();
    return acc;
  }, {});
}

function el(tag, className = "", text = "") {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== "") node.textContent = text;
  return node;
}

function message(text, isError = false) {
  notice.textContent = text;
  notice.classList.toggle("error", isError);
  notice.classList.remove("hidden");
  window.clearTimeout(message.timer);
  message.timer = window.setTimeout(() => notice.classList.add("hidden"), 5000);
}

async function saveConfig() {
  await api("/api/config", {
    method: "PUT",
    body: JSON.stringify(state.config),
  });
  message("Config saved.");
}

async function previewPlan() {
  const plan = await api("/api/plan", {
    method: "POST",
    body: JSON.stringify(state.config),
  });
  output.textContent = JSON.stringify(plan, null, 2);
  message(`Plan contains ${plan.steps.length} steps.`);
}

async function applyPlan() {
  const result = await api("/api/apply", {
    method: "POST",
    body: JSON.stringify(state.config),
  });
  output.textContent = JSON.stringify(result, null, 2);
  message(result.dryRun ? "Dry-run completed. Start daemon with --apply to execute." : "Apply completed.");
}

document.querySelectorAll(".nav-item").forEach((button) => {
  button.addEventListener("click", () => {
    state.tab = button.dataset.tab;
    render();
  });
});

$("#reload").addEventListener("click", () => load().catch((error) => message(error.message, true)));
$("#save").addEventListener("click", () => saveConfig().catch((error) => message(error.message, true)));
$("#preview").addEventListener("click", () => previewPlan().catch((error) => message(error.message, true)));
$("#apply").addEventListener("click", () => applyPlan().catch((error) => message(error.message, true)));
$("#clear-output").addEventListener("click", () => output.textContent = "No plan generated yet.");

load().catch((error) => {
  message(error.message, true);
  api("/api/default-config").then((cfg) => {
    state.config = cfg;
    render();
  });
});
