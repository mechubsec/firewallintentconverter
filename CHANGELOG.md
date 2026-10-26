# Changelog

All notable changes to this project will be documented in this file.

## [1.3.0] - 2026-10-26

Conversion-fidelity release. Several fixes change generated policy and NAT
behaviour; review the **Security** section before re-exporting configurations
made with 1.2.x.

### Security
- Policies with `application any` next to specific services (PAN-OS
  `application any` + `service-https`, AWS SG, Azure NSG, GCP) converted to
  `match application any`, permitting every port. The services now define the
  match (#163).
- GCP, AWS SG and Azure NSG allow rules converted to `then deny` (the parsers
  emitted a non-schema action value) (#154).
- Output ends in `security policies default-policy deny-all` in set and XML
  (#139).
- Zones no longer get a blanket `host-inbound-traffic system-services ping`.
  Host-inbound access is converted per zone and interface from the source:
  FortiGate `allowaccess`/`ip6-allowaccess`, PAN-OS interface management
  profiles, ASA `ssh`/`http`/`telnet`/`icmp`, Huawei `service-manage`, SRX
  passthrough. Source-restricted management access (ASA source lines, PAN-OS
  `permitted-ip`, Huawei ACLs, ASA control-plane ACLs, FortiGate local-in deny
  policies) fails closed with a warning, since host-inbound cannot restrict
  sources (#138, #156).
- Undefined services whose name matches another vendor's built-in (e.g. a
  FortiGate `web-browsing`) no longer become that built-in; built-in detection
  is scoped to the source vendor (#152).
- Analysis: shadow, redundancy, merge and consolidation checks respect
  negated addresses, so "everything except X" is no longer reported as
  equal to X (#124).

### Added
- SRX `system services` (ssh, web-management https/http, netconf, custom
  ports) generated from converted management access (#156).
- One-way static NAT (PAN-OS `bi-directional no`, ASA `unidirectional`) as a
  `port no-translation` source pool with `host-address-base` for subnets
  (#149).
- Check Point static NAT: automatic pairs collapse into Junos static NAT;
  lone rows convert one-way (#148).
- FortiGate policy NAT in config order with `source-nat off` exemptions,
  protocol/port matches, and ippool modes (`port no-translation`,
  `block-allocation`, `deterministic`) (#115).
- Interface-scoped destination NAT rule-sets (`from interface`) for
  FortiGate VIPs (#106).
- Terraform export emits the global address book as
  `junos_security_address_book` (#129).
- GCP implied allow-egress and deny-ingress rules (#154).
- PAN-OS and ASA static NAT with `from zone` and proxy ARP (#136, #146, #147);
  proxy ARP for NAT addresses on connected subnets (#135).

### Fixed
- FortiGate interfaces: aggregates map to `aeN` everywhere (and the XML
  creates the LAG), DHCP interfaces get `family inet dhcp`, IPv6 addresses
  are kept (#132).
- FortiGate: policies and NAT in config order (#126), source NAT for
  `nat enable` (#120), VIP/vipgrp destinations resolved (#119), multi-range
  services (#118), every L3 interface zoned when a rule uses `any` (#133),
  sctp/icmp port-forward VIPs skipped instead of aborting (#113), masks kept
  and VIP NAT scoped to its ingress zone (#102).
- One NAT plan shared by set and XML output (#134); NAT warnings carry a real
  severity (#140); range match addresses expand to covering prefixes (#112).
- Negated source/destination addresses honoured (#117); SRX parser reads
  address-excluded and deactivated policies (#130); XML deactivates disabled,
  unmapped-application and undefined-reference policies (#128).
- Huawei `action no-nat` kept as source NAT off (#137); ASA twice NAT and NAT
  exemptions (#147).
- GRE maps to the predefined `junos-gre` application (#153).
- Terraform export: policies per zone pair, negation kept (#131).
- Zone editor host-inbound checkboxes bound to the zone's access data (#157).

### Changed
- pyez-bridge: all-or-nothing load and same-session commit; the candidate is
  locked before `/confirm` and `/rollback` commit it (#81, #83, #84).
- Local-only LLM mode enforced at the network boundary, with CSP and consent
  fixes (#79).
- Dependencies: vite 8.3.5, vitest 4.1.12, source-map-js 1.2.2.

## [1.2.2] - 2026-08-26

Supply-chain and CI only. No behaviour change in the converter itself; the
version stamp in generated set/XML output and the PDF report moves to 1.2.2.

### Security
- Bumped nanoid to 3.3.18 for [GHSA-2v37-7h3g-55p8](https://github.com/advisories/GHSA-2v37-7h3g-55p8)
  (CWE-835, CVSS 5.9). It reaches the tree transitively through vite -> postcss.
  The 1.2.1-era postcss bump did **not** clear it: postcss 8.5.25 declares
  `nanoid: ^3.3.16` and the lockfile resolved to 3.3.16, still inside the
  vulnerable range. Lockfile-only change; postcss stays at 8.5.25. Not
  reachable in practice — the loop needs a custom generator called with size 0,
  and postcss mints fixed-length identifiers — but cleared so the audit report
  stays trustworthy. `npm audit` now reports 0 vulnerabilities.
- Bumped postcss 8.5.15 -> 8.5.25.

### Changed
- njsscan is a hard CI gate instead of report-only. It structurally
  false-positives on a repo that *generates* firewall config full of the words
  "secret" and "api key", so the 13 known sites carry individual
  `// njsscan-ignore: <rule>` suppressions with written justifications rather
  than the scanner being disabled repo-wide. Every rule stays live everywhere
  else, and a genuinely new finding now blocks the build.
- Moved `actions/checkout`, `setup-node`, and `setup-python` off deprecated
  Node 20 runners.

## [1.2.1] - 2026-07-19

### Added
- Version and assisting-LLM provenance stamps: `src/version.js` sources `APP_VERSION` from `package.json` and stamps it into the UI footer, the top line of every generated output file (set + XML), and the PDF report, alongside the assisting model label when one was used.
- Rulebase analysis suite: exposure and dangerous-service checks, policy correctness and coverage checks, device-plane and VPN hardening checks, operational cleanup checks, NAT shadow detection, and redundant-rule parity with shadowed rules (order, bulk action, explainer).
- Bulk actions for NAT-shadow, undefined-reference, and zone findings, plus an Ignore action for advisory findings.
- Target architecture as an explicit conversion input, driving skill-correct MNHA output.
- Reference-integrity gate and a conversion fidelity manifest.
- `security policies global` output mode, now the default.
- SSL-VPN / remote-access interface target, and PAN-OS sub-interfaces mapped to tagged units on the parent SRX port.
- CI: security-review SAST caller (gitleaks + semgrep + njsscan).

### Changed
- Source NAT is pinned to the provider interface's address; source match address-groups and service protocol/port are preserved.
- Backup static routes use `qualified-next-hop` instead of ECMP.
- Policies referencing unmapped App-IDs are deactivated rather than emitted as active `tcp/1`.
- Licensing consolidated to MIT-only; mechub branding applied across the web application.

### Fixed
- Zone-pair and deployment-mode selectors take effect immediately.
- Non-literal interface IPv6/IPv4 no longer blocks conversion.
- NAT pools emit literal addresses, never object names.
- Set-output gate rejects malformed IPv4, failing closed.
- Screens preserve PAN alarm-rate and attach to the zone.
- UI-only `_analysisFindings` no longer blocks conversion.
- Remote Access VPN report section is grouped after Security Policies.

## [1.2.0] - 2026-04-16

### Added
- Expanded `src/data/app-mappings.json` from 236 to 280+ canonical apps covering cloud SaaS (Adobe Creative Cloud, Apple APNs, Google FCM, Salesforce, ServiceNow, Dropbox, Box, GitHub, Bitbucket, Okta, Azure AD, AWS API, Google Workspace, Jira, Zendesk, HubSpot, Workday, Concur, Twilio, PagerDuty, Splunk Cloud, Datadog), collaboration (WeChat, Line, GoToMeeting), management/infrastructure (TACACS+, sFlow, DNS-over-TLS, DNS-over-HTTPS, syslog-TLS, LDAP-TLS, RADIUS Accounting), remote access/VPN (Cisco AnyConnect, GlobalProtect, Pulse Secure, FortiClient VPN, SSTP, IKEv2), database/middleware (ActiveMQ, NATS, ZooKeeper, ScyllaDB, Couchbase, Hazelcast, Pulsar, Hive), and industrial/ICS protocols (Modbus, DNP3, IEC-104, S7comm, BACnet, Niagara Fox).
- Multi-vendor support broadened to include Check Point, SonicWall, and Huawei USG aliases on 40 core protocols (HTTP, HTTPS, SSH, DNS, LDAP, NTP, etc.) — previously these vendors had null fatcat keys and could not resolve anything against the mapping table.
- New `getJunosEmission(appName, sourceVendor)` helper returning a discriminated union (`predefined` / `custom` / `null`) that powers concrete custom-application emission when a canonical entry has known ports but no Junos predefined equivalent.

### Changed
- Placeholder unmapped-application output now funnels into a single `INTERVIEW REQUIRED` block with `<name>-UNMAPPED` placeholders, instead of emitting a per-app `destination-port 1` definition line with a `Customfwic` suffix. Each unmapped app appears once with clearly-labeled sentinel values and a TODO comment naming the original vendor app.
- `mapAppToJunos()` now passes through input names that are already valid Junos predefined applications (e.g. `junos-ldap` stays `junos-ldap` instead of being corrupted into `junos-ldapCustomfwic`).
- Multi-port canonical apps (e.g. Apple APNs on 5223/2195/2196) emit an `application-set` with one sub-application per port, wrapped under a single canonical name the policy can reference.

### Fixed
- `_buildIndex()` in `src/utils/app-mappings.js` now tolerates vendor entries with `name: null`, required by the expanded schema that declares which vendors have no published signature for an app.
- `autoGenerateMissingAppDefinitions()` check ordering: standard predefined Junos applications (`junos-https`, `junos-ldap`, etc.) are no longer incorrectly aliased as `custom-*` definitions.

## [1.1.0.0] - 2026-03-28

### Added
- **DESIGN.md** — Design system documentation with color conventions, typography, spacing, and component patterns
- **LAG/aggregate interface support** — All 7 vendor parsers (PAN-OS, FortiGate, Cisco ASA, SRX, Huawei, SonicWall, Check Point) now parse LAG/LACP/port-channel/bond interfaces, with SRX ae converter output and Interface Mapper visual grouping
- **Conversion Report** — 8-section tabbed report under Output: rule count comparison, unused objects, shadowed rules, AI-disabled rules, migration delta dashboard, exportable summary, per-command decision tracking, rollback plan generation
- **Light/dark theme toggle** — User-selectable themes with OS preference detection, TopBar toggle, and localStorage persistence
- **3-node and 4-node MNHA support** — Extended chassis cluster / MNHA generation beyond 2-node configurations
- **Hardware capacity validation** — Post-conversion validation against SRX model limits (policies, sessions, zones, NAT rules, address objects)
- **Pre/post migration checklist** — Auto-generated task checklist based on parsed config features (certificates, JIMS, IDP, SecIntel, RADIUS, VPN, NAT, HA, syslog)
- **Interface mapping templates** — Save/load mapping profiles per source→target model pair for repeated migrations
- **Config version diff** — Side-by-side diff comparison of SRX outputs with LCS-based line diff and green/red highlighting
- **Policy dependency graph** — Interactive SVG showing address/service object relationships to policies with force-directed layout
- **Terraform/Ansible export** — Generate Junos Terraform provider resources or Ansible junos_config playbooks from SRX output
- **vSRX integration test harness** — PyEZ-based test script that pushes all 11 sample configs to a live vSRX and verifies commit

### Fixed
- **~45 SRX converter bugs** found during live vSRX testing (11/11 sample configs now commit clean):
  - UTM profile names avoid Junos reserved identifiers (`junos-av-*` → `custom-av-*`)
  - UTM web-filtering uses correct `juniper-enhanced profile` hierarchy
  - IKE proposals use `sha-256` (not `hmac-sha-256-128`)
  - IPsec proposals use `hmac-sha-256-128` correctly
  - NAT match addresses resolved from names to IPs
  - NAT pool addresses resolved for all vendor address field variants
  - Global policies use `security policies global policy` syntax when zone is `any`
  - Default-policy `permit-all` emitted when global policies exist
  - OSPF/OSPF3 interface names mapped through `mapInterfaceName` (loopback→lo0)
  - OSPF areas with no mapped interfaces skipped to prevent commit errors
  - Application-sets avoid name conflicts with member applications
  - `any` deduplicated in policy match (Junos constraint)
  - Interface deduplication prevents same interface in multiple zones
  - Address-book entries with host IP + non-host mask corrected to /32
  - Platform-dependent `junos-*` apps (mysql, mssql, oracle, postgres, quic, ocsp) auto-defined as `custom-*` aliases
  - Uppercase app names mapped for Huawei (HTTP→junos-http)
  - Firewall filter addresses resolved from names to IPs
  - Static route `metric` corrected to `preference`
  - Screen/IDP values clamped to Junos-valid ranges
  - SSL proxy and JIMS/user-ID generation skipped (requires manual PKI/server setup)
  - Custom application names sanitized (no leading digits, no dots)
  - Service objects with comma-separated ports converted to application-sets

### Changed
- **CSS transitions** — All 22 `transition: all` instances replaced with specific property transitions
- **Touch targets** — Toolbar buttons increased to 36px min, sidebar toggle to 32px min
- **Font sizes** — Status labels 9→10px, btn-sm 11→12px, nav items 12→13px, sidebar headers 11→12px
- **Empty states** — Added SVG icons and headings to WarningsPanel, SRXOutput, ContentRouter empty states
- **Accessibility** — Added `prefers-reduced-motion` media query
