import { describe, it, expect } from 'vitest';
import { parseGcpFirewallRules } from '../src/parsers/gcp-fw-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { AnalysisEngine } from '../src/analysis/config-analyzer.js';
import { validateSrxOutput } from '../src/validators/srx-validator.js';

const NETWORK = 'projects/p/global/networks/vpc1';
const sshIngress = {
  name: 'allow-ssh', network: NETWORK, direction: 'INGRESS', priority: 1000,
  sourceRanges: ['10.0.0.0/8'], allowed: [{ IPProtocol: 'tcp', ports: ['22'] }],
};
const egressDenyAll = {
  name: 'deny-all-egress', network: NETWORK, direction: 'EGRESS', priority: 65000,
  destinationRanges: ['0.0.0.0/0'], denied: [{ IPProtocol: 'all' }],
};

const implicitOf = (rules) => parseGcpFirewallRules(JSON.stringify(rules))
  .intermediateConfig.security_policies.filter(p => p._implicit && p.name.startsWith('Implicit: GCP'));

describe('GCP implied rules (#154)', () => {
  it('appends implied allow-egress and deny-ingress after parsed rules', () => {
    const { security_policies: policies } = parseGcpFirewallRules(JSON.stringify([sshIngress])).intermediateConfig;
    expect(policies.map(p => p._implicit)).toEqual([undefined, true, true]);
    const [ingress, egress] = policies.slice(1);
    expect(egress).toMatchObject({ action: 'allow', src_zones: ['net-vpc1'], dst_zones: ['any'], services: ['any'] });
    expect(ingress).toMatchObject({ action: 'deny', src_zones: ['any'], dst_zones: ['net-vpc1'], services: ['any'] });
  });

  it('adds implied rules per network, every ingress deny before any egress allow', () => {
    const other = { ...sshIngress, name: 'ssh2', network: 'projects/p/global/networks/vpc2' };
    const implicit = implicitOf([sshIngress, other]);
    expect(implicit).toHaveLength(4);
    // First match wins on the SRX: vpc1's egress allow must not pass vpc1 -> vpc2 ahead of vpc2's ingress deny.
    expect(implicit.map(p => p.action)).toEqual(['deny', 'deny', 'allow', 'allow']);
  });

  it('always emits the implied allow-egress, shadowed by an explicit egress deny-all', () => {
    const { security_policies: policies } = parseGcpFirewallRules(JSON.stringify([sshIngress, egressDenyAll])).intermediateConfig;
    const order = policies.map(p => p.name);
    expect(order).toContain('Implicit: GCP allow egress (vpc1)');
    expect(order.indexOf('deny-all-egress')).toBeLessThan(order.indexOf('Implicit: GCP allow egress (vpc1)'));
  });

  it('does not flag the implied allow-egress as a permissive user rule', () => {
    const { intermediateConfig } = parseGcpFirewallRules(JSON.stringify([sshIngress]));
    expect(AnalysisEngine._permissivePolicies(intermediateConfig).count).toBe(0);
    const { warnings } = validateSrxOutput(intermediateConfig, '');
    expect(warnings.some(w => /very permissive/.test(w.message))).toBe(false);
  });

  it('emits the egress permit and ingress deny in SRX output', () => {
    const { intermediateConfig } = parseGcpFirewallRules(JSON.stringify([sshIngress]));
    const { commands } = convertToSrxSetCommands(intermediateConfig);
    const policyLine = (name, clause) => `set security policies global policy ${name} ${clause}`;
    expect(commands).toContain(policyLine('Implicit-GCP-allow-egress-vpc1', 'then permit'));
    expect(commands).toContain(policyLine('Implicit-GCP-allow-egress-vpc1', 'match from-zone net-vpc1'));
    expect(commands).toContain(policyLine('Implicit-GCP-deny-ingress-vpc1', 'then deny'));
    // Control: the parsed allow rule is a permit, not a deny, and keeps its service.
    expect(commands).toContain(policyLine('allow-ssh', 'then permit'));
    expect(commands).toContain(policyLine('allow-ssh', 'match application tcp-22'));
  });

  describe('ordering', () => {
    const net = name => `projects/p/global/networks/${name}`;
    const policiesOf = rules => parseGcpFirewallRules(JSON.stringify(rules)).intermediateConfig.security_policies;
    const names = rules => policiesOf(rules).map(p => p.name);

    it('puts every network ingress rule before every egress rule', () => {
      const vpc1AllowEgress = {
        name: 'v1-allow-egress', network: net('vpc1'), direction: 'EGRESS', priority: 100,
        destinationRanges: ['0.0.0.0/0'], allowed: [{ IPProtocol: 'all' }],
      };
      const vpc2Ssh = { ...sshIngress, name: 'v2-ssh', network: net('vpc2'), priority: 1000 };
      const order = names([vpc1AllowEgress, vpc2Ssh]);
      const egressAllow = order.indexOf('v1-allow-egress');
      expect(order.indexOf('v2-ssh')).toBeLessThan(egressAllow);
      expect(order.indexOf('Implicit: GCP deny ingress (vpc2)')).toBeLessThan(egressAllow);
      expect(order.indexOf('Implicit: GCP deny ingress (vpc1)')).toBeLessThan(egressAllow);
      const { security_policies: policies } = parseGcpFirewallRules(JSON.stringify([vpc1AllowEgress, vpc2Ssh])).intermediateConfig;
      expect(policies.map(p => p._rule_index)).toEqual(policies.map((_, index) => index));
    });

    it('sorts an explicit 65535 ingress allow after the implied ingress deny', () => {
      const late = { ...sshIngress, name: 'late-allow', priority: 65535 };
      const order = names([late]);
      expect(order.indexOf('Implicit: GCP deny ingress (vpc1)')).toBeLessThan(order.indexOf('late-allow'));
    });

    it('sorts deny before allow at equal priority and an explicit 65535 egress deny before the implied allow', () => {
      const allow = { ...sshIngress, name: 'same-allow', priority: 500 };
      const deny = { ...sshIngress, name: 'same-deny', priority: 500, allowed: undefined, denied: [{ IPProtocol: 'tcp', ports: ['22'] }] };
      const order = names([allow, deny]);
      expect(order.indexOf('same-deny')).toBeLessThan(order.indexOf('same-allow'));
      const lateEgressDeny = { ...egressDenyAll, name: 'late-egress-deny', priority: 65535, destinationRanges: ['10.0.0.0/8'] };
      const lateOrder = names([lateEgressDeny]);
      expect(lateOrder.indexOf('late-egress-deny')).toBeLessThan(lateOrder.indexOf('Implicit: GCP allow egress (vpc1)'));
    });

    it('keeps perimeter egress order: allow 100 before deny-all 1000', () => {
      const allow = { name: 'egress-allow', network: net('vpc1'), direction: 'EGRESS', priority: 100,
        destinationRanges: ['10.0.0.0/8'], allowed: [{ IPProtocol: 'all' }] };
      const deny = { ...egressDenyAll, name: 'egress-deny-all', priority: 1000 };
      const order = names([deny, allow]);
      expect(order.indexOf('egress-allow')).toBeLessThan(order.indexOf('egress-deny-all'));
    });

    it('warns once, naming networks, when enabled explicit egress deny rules exist', () => {
      const warningsOf = rules => parseGcpFirewallRules(JSON.stringify(rules)).warnings.filter(w => /Egress deny rules/.test(w.message));
      const other = { ...egressDenyAll, name: 'deny-2', network: net('vpc2') };
      const hit = warningsOf([sshIngress, egressDenyAll, other]);
      expect(hit).toHaveLength(1);
      expect(hit[0].message).toContain('vpc1, vpc2');
      expect(warningsOf([egressDenyAll])).toHaveLength(1);
      expect(warningsOf([{ ...egressDenyAll, disabled: true }])).toHaveLength(0);
      expect(warningsOf([sshIngress])).toHaveLength(0);
    });
  });
});
