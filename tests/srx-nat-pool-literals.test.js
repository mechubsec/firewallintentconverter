/**
 * NAT Pool Literal Addresses (Issue #35)
 * Tests correctness fix: NAT pools must only contain literal IP addresses/prefixes,
 * never object names or FQDNs.
 */

import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';
import { validateSetOutput } from '../src/security/junos-output-validation.js';

describe('NAT Pool Literal Addresses (Issue #35)', () => {
  it.each([
    ['source', { src_addresses: ['ghost', '192.0.2.0/24'] }, 'not a known address object'],
    ['source', { src_addresses: ['fqdn', '192.0.2.0/24'] }, 'resolves to FQDN'],
    ['source', { translated_src: { type: 'static', address: 'ghost' } }, 'fell back to interface NAT'],
    ['source', { translated_src: { type: 'dynamic-ip-pool', addresses: ['ghost'] } }, 'not a known address object'],
    ['destination', { translated_dst: { address: 'ghost' } }, 'Destination NAT rule'],
    ['static', { translated_src: { address: 'ghost' } }, 'Static NAT rule'],
  ])('reports usable %s NAT warnings for %j', (type, overrides, message) => {
    const config = {
      zones: [{ name: 'trust' }, { name: 'untrust' }],
      address_objects: [{ name: 'fqdn', value: 'host.example.invalid' }],
      nat_rules: [{
        name: 'warning-case', type, enabled: true,
        src_zones: ['trust'], dst_zones: ['untrust'],
        src_addresses: ['192.0.2.0/24'], dst_addresses: ['203.0.113.10'],
        ...overrides,
      }],
    };
    for (const result of [convertToSrxSetCommands(config), buildSrxXml(config)]) {
      const natWarnings = result.warnings.filter(w => w.element?.startsWith('nat/'));
      expect(natWarnings.length).toBeGreaterThan(0);
      expect(natWarnings.some(w => w.message?.includes(message))).toBe(true);
      for (const warning of natWarnings) {
        expect(warning.severity).toBe('warning');
        expect(warning.element).toBe(`nat/${type}/warning-case`);
        expect(typeof warning.message).toBe('string');
        expect(warning.message.length).toBeGreaterThan(0);
        expect(typeof warning.suggestion).toBe('string');
      }
    }
  });

  describe('Static Source NAT', () => {
    it('should fall back to interface NAT when translated address is undefined', () => {
      const config = {
        zones: [
          { name: 'trust', interfaces: ['ge-0/0/0'] },
          { name: 'untrust', interfaces: ['ge-0/0/1'] },
        ],
        nat_rules: [
          {
            name: 'static-snat-undefined',
            type: 'source',
            enabled: true,
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['10.0.1.0/24'],
            dst_addresses: ['any'],
            translated_src: {
              type: 'static',
              address: 'UNDEFINED-POOL-OBJ', // unknown object
            },
          },
        ],
      };

      const result = convertToSrxSetCommands(config);
      const natCommands = result.commands.filter(c => c.includes('security nat source'));

      // Must NOT emit a pool with the undefined object name
      expect(natCommands.some(c => c.includes('address UNDEFINED-POOL-OBJ'))).toBe(false);

      // Must fall back to interface NAT
      expect(natCommands.some(c => c.includes('then source-nat interface'))).toBe(true);

      // Must have a caveat comment
      expect(result.commands.some(c =>
        c.includes('#') && c.toLowerCase().includes('nat') && c.includes('UNDEFINED-POOL-OBJ')
      )).toBe(true);

      // Must have a warning
      expect(result.warnings.some(w =>
        w.severity === 'warning' && w.element.startsWith('nat/') && w.message.includes('UNDEFINED-POOL-OBJ')
      )).toBe(true);
    });

    it('should emit normalized pool address when translated address resolves to a literal', () => {
      const config = {
        zones: [
          { name: 'trust', interfaces: ['ge-0/0/0'] },
          { name: 'untrust', interfaces: ['ge-0/0/1'] },
        ],
        address_objects: [
          { name: 'StaticSourceIP', value: '203.0.113.10' }, // bare IP
        ],
        nat_rules: [
          {
            name: 'static-snat-resolved',
            type: 'source',
            enabled: true,
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['10.0.1.0/24'],
            dst_addresses: ['any'],
            translated_src: {
              type: 'static',
              address: 'StaticSourceIP', // resolvable object
            },
          },
        ],
      };

      const result = convertToSrxSetCommands(config);
      const natCommands = result.commands.filter(c => c.includes('security nat source'));

      // Must emit pool with normalized bare IP (add /32)
      expect(natCommands.some(c => c.includes('address 203.0.113.10/32'))).toBe(true);

      // Must use pool NAT, not interface NAT
      expect(natCommands.some(c => c.match(/then source-nat pool \S+/))).toBe(true);

      // No warnings for this resolved case
      expect(result.warnings.filter(w => w.element.startsWith('nat/') && w.message.includes('could not be resolved'))).toHaveLength(0);
    });

    it('should preserve prefix notation when translated address has a prefix', () => {
      const config = {
        zones: [
          { name: 'trust', interfaces: ['ge-0/0/0'] },
          { name: 'untrust', interfaces: ['ge-0/0/1'] },
        ],
        address_objects: [
          { name: 'SourceRange', value: '203.0.113.0/24' }, // already has prefix
        ],
        nat_rules: [
          {
            name: 'static-snat-prefix',
            type: 'source',
            enabled: true,
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['10.0.1.0/24'],
            dst_addresses: ['any'],
            translated_src: {
              type: 'static',
              address: 'SourceRange',
            },
          },
        ],
      };

      const result = convertToSrxSetCommands(config);
      const natCommands = result.commands.filter(c => c.includes('security nat source'));

      // Must preserve the prefix as-is
      expect(natCommands.some(c => c.includes('address 203.0.113.0/24'))).toBe(true);
    });

    // Fix 3: IPv6 normalization
    it('should normalize bare IPv6 address to /128 in static source NAT', () => {
      const config = {
        zones: [
          { name: 'trust', interfaces: ['ge-0/0/0'] },
          { name: 'untrust', interfaces: ['ge-0/0/1'] },
        ],
        address_objects: [
          { name: 'IPv6Source', value: '2001:db8::1' }, // bare IPv6, no prefix
        ],
        nat_rules: [
          {
            name: 'static-snat-ipv6',
            type: 'source',
            enabled: true,
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['10.0.1.0/24'],
            dst_addresses: ['any'],
            translated_src: {
              type: 'static',
              address: 'IPv6Source',
            },
          },
        ],
      };

      const result = convertToSrxSetCommands(config);
      const natCommands = result.commands.filter(c => c.includes('security nat source'));

      // Must emit pool with normalized IPv6 (add /128)
      expect(natCommands.some(c => c.includes('address 2001:db8::1/128'))).toBe(true);
    });
  });

  describe('Destination NAT', () => {
    it('should skip destination NAT when translated address is undefined', () => {
      const config = {
        zones: [
          { name: 'untrust', interfaces: ['ge-0/0/1'] },
          { name: 'trust', interfaces: ['ge-0/0/0'] },
        ],
        nat_rules: [
          {
            name: 'dnat-undefined',
            type: 'destination',
            enabled: true,
            src_zones: ['untrust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['198.51.100.1'],
            translated_dst: {
              address: 'GHOST-SERVER', // unknown object
            },
          },
        ],
      };

      const result = convertToSrxSetCommands(config);
      const natCommands = result.commands.filter(c => c.includes('security nat destination'));

      // Must NOT emit a pool with the undefined object name
      expect(natCommands.some(c => c.includes('address GHOST-SERVER'))).toBe(false);

      // Must NOT emit then destination-nat for this rule
      expect(natCommands.some(c => c.includes('then destination-nat pool'))).toBe(false);

      // Fix 1: Must NOT emit ANY match line for this rule (the whole rule is skipped)
      expect(natCommands.some(c => c.includes('rule dnat-undefined match'))).toBe(false);

      // Must have a caveat comment
      expect(result.commands.some(c =>
        c.includes('#') && c.toLowerCase().includes('nat') && c.includes('GHOST-SERVER')
      )).toBe(true);

      // Must have a warning
      expect(result.warnings.some(w =>
        w.severity === 'warning' && w.element.startsWith('nat/') && w.message.includes('GHOST-SERVER')
      )).toBe(true);

      // Fix 1: The full output must pass validateSetOutput (no match-without-then)
      expect(() => validateSetOutput(result.commands)).not.toThrow();
    });

    it('should emit normalized pool address when translated address resolves to a literal', () => {
      const config = {
        zones: [
          { name: 'untrust', interfaces: ['ge-0/0/1'] },
          { name: 'trust', interfaces: ['ge-0/0/0'] },
        ],
        address_objects: [
          { name: 'InternalServer', value: '198.51.100.5' }, // bare IP
        ],
        nat_rules: [
          {
            name: 'dnat-resolved',
            type: 'destination',
            enabled: true,
            src_zones: ['untrust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['203.0.113.10'],
            translated_dst: {
              address: 'InternalServer', // resolvable object
            },
          },
        ],
      };

      const result = convertToSrxSetCommands(config);
      const natCommands = result.commands.filter(c => c.includes('security nat destination'));

      // Must emit pool with normalized bare IP (add /32)
      expect(natCommands.some(c => c.includes('address 198.51.100.5/32'))).toBe(true);

      // Must emit then destination-nat
      expect(natCommands.some(c => c.includes('then destination-nat pool'))).toBe(true);

      // No warnings for this resolved case
      expect(result.warnings.filter(w => w.element.startsWith('nat/') && w.message.includes('could not be resolved'))).toHaveLength(0);
    });

    it('should handle destination NAT with port translation', () => {
      const config = {
        zones: [
          { name: 'untrust', interfaces: ['ge-0/0/1'] },
          { name: 'trust', interfaces: ['ge-0/0/0'] },
        ],
        address_objects: [
          { name: 'WebServer', value: '198.51.100.10' },
        ],
        nat_rules: [
          {
            name: 'dnat-with-port',
            type: 'destination',
            enabled: true,
            src_zones: ['untrust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['203.0.113.20'],
            match_port: '80',
            translated_dst: {
              address: 'WebServer',
            },
            translated_port: '8080',
          },
        ],
      };

      const result = convertToSrxSetCommands(config);
      const natCommands = result.commands.filter(c => c.includes('security nat destination'));

      // Must emit pool with literal IP
      expect(natCommands.some(c => c.includes('address 198.51.100.10/32'))).toBe(true);

      // Must emit port translation
      expect(natCommands.some(c => c.includes('address port 8080'))).toBe(true);

      // Must emit then destination-nat
      expect(natCommands.some(c => c.includes('then destination-nat pool'))).toBe(true);
    });

    // Fix 3: IPv6 normalization for destination NAT
    it('should normalize bare IPv6 address to /128 in destination NAT', () => {
      const config = {
        zones: [
          { name: 'untrust', interfaces: ['ge-0/0/1'] },
          { name: 'trust', interfaces: ['ge-0/0/0'] },
        ],
        address_objects: [
          { name: 'IPv6Server', value: '2001:db8::10' }, // bare IPv6
        ],
        nat_rules: [
          {
            name: 'dnat-ipv6',
            type: 'destination',
            enabled: true,
            src_zones: ['untrust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['2001:db8::20'],
            translated_dst: {
              address: 'IPv6Server',
            },
          },
        ],
      };

      const result = convertToSrxSetCommands(config);
      const natCommands = result.commands.filter(c => c.includes('security nat destination'));

      // Must emit pool with normalized IPv6 (add /128)
      expect(natCommands.some(c => c.includes('address 2001:db8::10/128'))).toBe(true);

      // Must emit then destination-nat
      expect(natCommands.some(c => c.includes('then destination-nat pool'))).toBe(true);
    });
  });

  describe('Output Gate Validation', () => {
    it('should reject NAT pool address with non-literal object name', () => {
      const invalidCommands = [
        'set security nat source pool test-pool address SOME-OBJECT-NAME',
      ];

      expect(() => validateSetOutput(invalidCommands)).toThrow(/malformed|invalid/i);
    });

    it('should reject NAT pool address with FQDN', () => {
      const invalidCommands = [
        'set security nat destination pool dnat-pool address server.example.com',
      ];

      expect(() => validateSetOutput(invalidCommands)).toThrow(/malformed|invalid/i);
    });

    it('should accept NAT pool address with valid IPv4 address', () => {
      const validCommands = [
        'set security nat source pool test-pool address 203.0.113.10/32',
      ];

      expect(() => validateSetOutput(validCommands)).not.toThrow();
    });

    it('should accept NAT pool address with valid IPv4 prefix', () => {
      const validCommands = [
        'set security nat destination pool dnat-pool address 198.51.100.0/24',
      ];

      expect(() => validateSetOutput(validCommands)).not.toThrow();
    });

    it('should accept NAT pool with address port syntax', () => {
      const validCommands = [
        'set security nat destination pool dnat-pool address 198.51.100.5/32',
        'set security nat destination pool dnat-pool address port 8080',
      ];

      expect(() => validateSetOutput(validCommands)).not.toThrow();
    });

    it('should accept IPv6 NAT pool addresses', () => {
      const validCommands = [
        'set security nat source pool ipv6-pool address 2001:db8::1/128',
      ];

      expect(() => validateSetOutput(validCommands)).not.toThrow();
    });

    it('should accept NAT pool with IP range (a-b format)', () => {
      const validCommands = [
        'set security nat source pool range-pool address 203.0.113.10-203.0.113.20',
      ];

      expect(() => validateSetOutput(validCommands)).not.toThrow();
    });

    // Fix 2: NAT rule completeness gate
    it('should reject NAT rule with match but no then', () => {
      const invalidCommands = [
        'set security nat destination rule-set RS rule R match destination-address 0.0.0.0/0',
      ];

      expect(() => validateSetOutput(invalidCommands)).toThrow(/match without a then/i);
    });

    it('should accept complete NAT rule with match and then', () => {
      const validCommands = [
        'set security nat destination rule-set RS from zone untrust',
        'set security nat destination rule-set RS rule R match destination-address 0.0.0.0/0',
        'set security nat destination rule-set RS rule R then destination-nat pool P',
      ];

      expect(() => validateSetOutput(validCommands)).not.toThrow();
    });
  });

  describe('Full Output Validation', () => {
    it('should produce output that passes validateSetOutput with undefined translated addresses', () => {
      const config = {
        zones: [
          { name: 'trust', interfaces: ['ge-0/0/0'] },
          { name: 'untrust', interfaces: ['ge-0/0/1'] },
        ],
        nat_rules: [
          {
            name: 'snat-undefined',
            type: 'source',
            enabled: true,
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['10.0.1.0/24'],
            dst_addresses: ['any'],
            translated_src: {
              type: 'static',
              address: 'UNDEFINED-OBJ',
            },
          },
          {
            name: 'dnat-undefined',
            type: 'destination',
            enabled: true,
            src_zones: ['untrust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['203.0.113.10'],
            translated_dst: {
              address: 'GHOST-OBJ',
            },
          },
        ],
      };

      const result = convertToSrxSetCommands(config);

      // The output must pass validation (no object names leaked into pools)
      expect(() => validateSetOutput(result.commands)).not.toThrow();
    });

    it('should produce output that passes validateSetOutput with resolved translated addresses', () => {
      const config = {
        zones: [
          { name: 'trust', interfaces: ['ge-0/0/0'] },
          { name: 'untrust', interfaces: ['ge-0/0/1'] },
        ],
        address_objects: [
          { name: 'SourceIP', value: '203.0.113.10' },
          { name: 'DestIP', value: '198.51.100.5' },
        ],
        nat_rules: [
          {
            name: 'snat-resolved',
            type: 'source',
            enabled: true,
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['10.0.1.0/24'],
            dst_addresses: ['any'],
            translated_src: {
              type: 'static',
              address: 'SourceIP',
            },
          },
          {
            name: 'dnat-resolved',
            type: 'destination',
            enabled: true,
            src_zones: ['untrust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['203.0.113.10'],
            translated_dst: {
              address: 'DestIP',
            },
          },
        ],
      };

      const result = convertToSrxSetCommands(config);

      // The output must pass validation
      expect(() => validateSetOutput(result.commands)).not.toThrow();
    });
  });
});
