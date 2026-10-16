import { describe, expect, it } from 'vitest';
import {
  findSecretsInText,
  isSanitizedSecretValue,
  isSecretBearingKey,
  redactConfigSecrets,
} from '../public/utils/secret-detection.js';
import { sanitizeConfig } from '../public/utils/engine.js';

const CASES = [
  ['panos nested PSK', '<pre-shared-key><key>PANOS-PSK-ORIGINAL</key></pre-shared-key>', 'PANOS-PSK-ORIGINAL', 'key'],
  ['panos direct PSK', '<pre-shared-key>PANOS-DIRECT-PSK-ORIGINAL</pre-shared-key>', 'PANOS-DIRECT-PSK-ORIGINAL', 'key'],
  ['panos API key', '<api-key>PANOS-API-ORIGINAL</api-key>', 'PANOS-API-ORIGINAL', 'key'],
  ['panos auth key', '<auth-key>PANOS-AUTH-ORIGINAL</auth-key>', 'PANOS-AUTH-ORIGINAL', 'key'],
  ['panos direct RADIUS secret', '<secret>PANOS-RADIUS-REAL-SECRET</secret>', 'PANOS-RADIUS-REAL-SECRET', 'key'],
  ['panos phash', '<phash>$6$PANOS-HASH-ORIGINAL</phash>', '$6$PANOS-HASH-ORIGINAL', 'hash'],
  ['panos password hash', '<password-hash>PANOS-PASSWORD-HASH-ORIGINAL</password-hash>', 'PANOS-PASSWORD-HASH-ORIGINAL', 'hash'],
  ['panos encrypted secret', '<encrypted-secret>PANOS-ENCRYPTED-ORIGINAL</encrypted-secret>', 'PANOS-ENCRYPTED-ORIGINAL', 'hash'],
  ['panos private key', '<private-key>PANOS-PRIVATE-ORIGINAL</private-key>', 'PANOS-PRIVATE-ORIGINAL', 'certificate'],
  ['panos certificate key', '<certificate-key>PANOS-CERT-SECRET-ORIGINAL</certificate-key>', 'PANOS-CERT-SECRET-ORIGINAL', 'certificate'],
  ['panos secret key', '<secret-key>PANOS-SECRET-KEY-ORIGINAL</secret-key>', 'PANOS-SECRET-KEY-ORIGINAL', 'certificate'],
  ['panos SSL key', '<ssl-key>PANOS-SSL-KEY-ORIGINAL</ssl-key>', 'PANOS-SSL-KEY-ORIGINAL', 'certificate'],
  ['panos XML SNMP community', '<community>PANOS-SNMP-ORIGINAL</community>', 'PANOS-SNMP-ORIGINAL', 'community'],
  ['generic attribute hash', 'password "$1$ATTRIBUTE-HASH-ORIGINAL"', '$1$ATTRIBUTE-HASH-ORIGINAL', 'hash'],

  ['fortigate encrypted password', 'set password ENC FGT-PASSWORD-ORIGINAL', 'ENC FGT-PASSWORD-ORIGINAL', 'hash'],
  ['fortigate quoted password', 'set password "FGT-QUOTED-PASSWORD-ORIGINAL"', 'FGT-QUOTED-PASSWORD-ORIGINAL', 'hash'],
  ['fortigate unquoted password', 'set password FGT-UNQUOTED-PASSWORD-ORIGINAL', 'FGT-UNQUOTED-PASSWORD-ORIGINAL', 'hash'],
  ['fortigate encrypted passwd', 'set passwd ENC FGT-PASSWD-ENC-ORIGINAL', 'ENC FGT-PASSWD-ENC-ORIGINAL', 'hash'],
  ['fortigate quoted passwd', 'set passwd "FGT-PASSWD-QUOTED-ORIGINAL"', 'FGT-PASSWD-QUOTED-ORIGINAL', 'hash'],
  ['fortigate unquoted passwd', 'set passwd FGT-PASSWD-UNQUOTED-ORIGINAL', 'FGT-PASSWD-UNQUOTED-ORIGINAL', 'hash'],
  ['fortigate psksecret', 'set psksecret "FGT-PSK-ORIGINAL"', 'FGT-PSK-ORIGINAL', 'key'],
  ['fortigate unquoted IPsec PSK', 'set psksecret FGT-IPSEC-PSK-ORIGINAL', 'FGT-IPSEC-PSK-ORIGINAL', 'key'],
  ['fortigate encrypted IPsec PSK', 'set psksecret ENC FGT-IPSEC-ENC-ORIGINAL', 'ENC FGT-IPSEC-ENC-ORIGINAL', 'key'],
  ['fortigate SNMP', 'set community "FGT-SNMP-ORIGINAL"', 'FGT-SNMP-ORIGINAL', 'community'],
  ['fortigate unquoted SNMP', 'set community FGT-SNMP-UNQUOTED-ORIGINAL', 'FGT-SNMP-UNQUOTED-ORIGINAL', 'community'],
  ['fortigate encrypted SNMP', 'set community ENC FGT-SNMP-ENC-ORIGINAL', 'ENC FGT-SNMP-ENC-ORIGINAL', 'community'],
  ['fortigate RADIUS secret', 'set secret "FGT-RADIUS-ORIGINAL"', 'FGT-RADIUS-ORIGINAL', 'key'],
  ['fortigate unquoted RADIUS secret', 'set secret FGT-RADIUS-UNQUOTED-ORIGINAL', 'FGT-RADIUS-UNQUOTED-ORIGINAL', 'key'],
  ['fortigate encrypted RADIUS secret', 'set secret ENC FGT-RADIUS-ENC-ORIGINAL', 'ENC FGT-RADIUS-ENC-ORIGINAL', 'key'],
  ['fortigate TACACS secret', 'set tacacs-secret "FGT-TACACS-ORIGINAL"', 'FGT-TACACS-ORIGINAL', 'key'],
  ['fortigate unquoted TACACS secret', 'set tacacs-secret FGT-TACACS-UNQUOTED-ORIGINAL', 'FGT-TACACS-UNQUOTED-ORIGINAL', 'key'],
  ['fortigate encrypted TACACS secret', 'set tacacs-secret ENC FGT-TACACS-ENC-ORIGINAL', 'ENC FGT-TACACS-ENC-ORIGINAL', 'key'],
  ['fortigate secondary secret', 'set secondary-secret "FGT-SECONDARY-ORIGINAL"', 'FGT-SECONDARY-ORIGINAL', 'key'],
  ['fortigate TACACS block key', 'config user tacacs+\n edit "tac-1"\n  set server "192.0.2.10"\n  set key "FGT-TACACS-REAL-SECRET"\n next\nend', 'FGT-TACACS-REAL-SECRET', 'key'],
  ['fortigate SNMP block name', 'config system snmp community\n edit 1\n  set name "FGT-SNMP-REAL-SECRET"\n next\nend', 'FGT-SNMP-REAL-SECRET', 'community'],

  ['asa ISAKMP key', 'crypto isakmp key ASA-PSK-ORIGINAL address 203.0.113.9', 'ASA-PSK-ORIGINAL', 'key'],
  ['asa enable secret', 'enable secret ASA-HASH-ORIGINAL', 'ASA-HASH-ORIGINAL', 'hash'],
  ['asa enable password encrypted', 'enable password ASA-ENABLE-PASSWORD-ORIGINAL encrypted', 'ASA-ENABLE-PASSWORD-ORIGINAL', 'hash'],
  ['asa password encrypted', 'password ASA-GENERIC-PASSWORD-ORIGINAL encrypted', 'ASA-GENERIC-PASSWORD-ORIGINAL', 'hash'],
  ['asa username password', 'username operator password ASA-PASSWORD-ORIGINAL', 'ASA-PASSWORD-ORIGINAL', 'hash'],
  ['asa username secret', 'username operator secret ASA-USER-SECRET-ORIGINAL', 'ASA-USER-SECRET-ORIGINAL', 'hash'],
  ['asa tunnel-group key', 'tunnel-group branch ipsec-attributes\n pre-shared-key ASA-TUNNEL-PSK-ORIGINAL', 'ASA-TUNNEL-PSK-ORIGINAL', 'key'],
  ['asa IKEv1 PSK', 'ikev1 pre-shared-key ASA-IKEV1-ORIGINAL', 'ASA-IKEV1-ORIGINAL', 'key'],
  ['asa IKEv2 local PSK', 'ikev2 local-authentication pre-shared-key ASA-IKEV2-LOCAL-ORIGINAL', 'ASA-IKEV2-LOCAL-ORIGINAL', 'key'],
  ['asa IKEv2 remote PSK', 'ikev2 remote-authentication pre-shared-key ASA-IKEV2-REMOTE-ORIGINAL', 'ASA-IKEV2-REMOTE-ORIGINAL', 'key'],
  ['asa SNMP community', 'snmp-server community ASA-SNMP-ORIGINAL', 'ASA-SNMP-ORIGINAL', 'community'],
  ['asa SNMP host community', 'snmp-server host inside 192.0.2.44 community ASA-HOST-COMM-SECRET version 2c', 'ASA-HOST-COMM-SECRET', 'community'],
  ['asa RADIUS key', 'radius-server host 192.0.2.2 key ASA-RADIUS-ORIGINAL', 'ASA-RADIUS-ORIGINAL', 'key'],
  ['asa TACACS key', 'tacacs-server host 192.0.2.3 key ASA-TACACS-ORIGINAL', 'ASA-TACACS-ORIGINAL', 'key'],
  ['ftd RADIUS secret', 'radius-server host 192.0.2.4 secret ASA-RADIUS-SECRET-ORIGINAL', 'ASA-RADIUS-SECRET-ORIGINAL', 'key'],
  ['asa AAA RADIUS key', 'aaa-server RADIUS protocol radius\naaa-server RADIUS (inside) host 192.0.2.5\n key ASA-AAA-RADIUS-ORIGINAL', 'ASA-AAA-RADIUS-ORIGINAL', 'key'],
  ['asa AAA TACACS key', 'aaa-server TACACS protocol tacacs+\naaa-server TACACS (inside) host 192.0.2.6\n key ASA-AAA-TACACS-ORIGINAL', 'ASA-AAA-TACACS-ORIGINAL', 'key'],
  ['asa XML private key', '<private-key>ASA-PRIVATE-FIELD-ORIGINAL</private-key>', 'ASA-PRIVATE-FIELD-ORIGINAL', 'certificate'],
  ['ftd certificate key', '<certificate-key>FTD-CERTIFICATE-KEY-ORIGINAL</certificate-key>', 'FTD-CERTIFICATE-KEY-ORIGINAL', 'certificate'],
  ['asa private-key block', '-----BEGIN RSA PRIVATE KEY-----\nASA-PRIVATE-BLOCK-ORIGINAL\n-----END RSA PRIVATE KEY-----', 'ASA-PRIVATE-BLOCK-ORIGINAL', 'certificate'],

  ['junos set ascii PSK', 'set security ike policy branch pre-shared-key ascii-text "JUNOS-PSK-ORIGINAL"', 'JUNOS-PSK-ORIGINAL', 'key'],
  ['junos encrypted PSK', 'set security ike policy branch pre-shared-key ascii-text "$9$JUNOS-ENCRYPTED-PSK-ORIGINAL"', '$9$JUNOS-ENCRYPTED-PSK-ORIGINAL', 'key'],
  ['junos hexadecimal PSK', 'set security ike policy branch pre-shared-key hexadecimal JUNOS-HEXADECIMAL-PSK-ORIGINAL', 'JUNOS-HEXADECIMAL-PSK-ORIGINAL', 'key'],
  ['junos unquoted PSK', 'set security ike policy branch pre-shared-key ascii-text JUNOS-UNQUOTED-PSK-ORIGINAL', 'JUNOS-UNQUOTED-PSK-ORIGINAL', 'key'],
  ['junos hierarchical PSK', 'pre-shared-key { ascii-text "JUNOS-HIERARCHICAL-PSK-ORIGINAL"; }', 'JUNOS-HIERARCHICAL-PSK-ORIGINAL', 'key'],
  ['junos encrypted password', 'set system login user ops authentication encrypted-password "$6$JUNOS-HASH-ORIGINAL"', '$6$JUNOS-HASH-ORIGINAL', 'hash'],
  ['junos hierarchical encrypted password', 'encrypted-password "$9$JUNOS-HIERARCHICAL-HASH-ORIGINAL";', '$9$JUNOS-HIERARCHICAL-HASH-ORIGINAL', 'hash'],
  ['junos SNMP community', 'set snmp community JUNOS-SNMP-ORIGINAL authorization read-only', 'JUNOS-SNMP-ORIGINAL', 'community'],
  ['junos hierarchical SNMP community', 'community JUNOS-HIERARCHICAL-SNMP-ORIGINAL { authorization read-only; }', 'JUNOS-HIERARCHICAL-SNMP-ORIGINAL', 'community'],
  ['junos RADIUS secret', 'set system radius-server 192.0.2.4 secret "JUNOS-RADIUS-ORIGINAL"', 'JUNOS-RADIUS-ORIGINAL', 'key'],
  ['junos hierarchical RADIUS secret', 'radius-server 192.0.2.4 { secret "JUNOS-HIERARCHICAL-RADIUS-ORIGINAL"; }', 'JUNOS-HIERARCHICAL-RADIUS-ORIGINAL', 'key'],
  ['junos TACPLUS secret', 'set system tacplus-server 192.0.2.5 secret "JUNOS-TACACS-ORIGINAL"', 'JUNOS-TACACS-ORIGINAL', 'key'],
  ['junos hierarchical TACPLUS secret', 'tacplus-server 192.0.2.5 { secret "JUNOS-HIERARCHICAL-TACACS-ORIGINAL"; }', 'JUNOS-HIERARCHICAL-TACACS-ORIGINAL', 'key'],
  ['junos authentication password', 'set snmp v3 usm local-engine user ops authentication-sha authentication-password "JUNOS-AUTH-ORIGINAL"', 'JUNOS-AUTH-ORIGINAL', 'key'],
  ['junos privacy password', 'set snmp v3 usm local-engine user ops privacy-aes128 privacy-password "JUNOS-PRIVACY-ORIGINAL"', 'JUNOS-PRIVACY-ORIGINAL', 'key'],
  ['junos authentication key', 'authentication-key "JUNOS-AUTH-KEY-ORIGINAL";', 'JUNOS-AUTH-KEY-ORIGINAL', 'key'],
  ['junos privacy key', 'privacy-key "JUNOS-PRIVACY-KEY-ORIGINAL";', 'JUNOS-PRIVACY-KEY-ORIGINAL', 'key'],
  ['junos private key field', 'private-key "JUNOS-PRIVATE-KEY-ORIGINAL";', 'JUNOS-PRIVATE-KEY-ORIGINAL', 'certificate'],
  ['junos certificate key field', 'certificate-key "JUNOS-CERTIFICATE-KEY-ORIGINAL";', 'JUNOS-CERTIFICATE-KEY-ORIGINAL', 'certificate'],

  ['checkpoint JSON shared secret', '"shared-secret":"CHECKPOINT-PSK-ORIGINAL"', 'CHECKPOINT-PSK-ORIGINAL', 'key'],
  ['checkpoint JSON password', '"password":"CHECKPOINT-PASSWORD-ORIGINAL"', 'CHECKPOINT-PASSWORD-ORIGINAL', 'hash'],
  ['checkpoint JSON password hash', '"password-hash":"CHECKPOINT-HASH-ORIGINAL"', 'CHECKPOINT-HASH-ORIGINAL', 'hash'],
  ['checkpoint JSON SNMP community', '"snmp-community":"CHECKPOINT-SNMP-ORIGINAL"', 'CHECKPOINT-SNMP-ORIGINAL', 'community'],
  ['checkpoint JSON RADIUS secret', '"radius-secret":"CHECKPOINT-RADIUS-ORIGINAL"', 'CHECKPOINT-RADIUS-ORIGINAL', 'key'],
  ['checkpoint text TACACS key', 'tacacs-key: CHECKPOINT-TACACS-ORIGINAL', 'CHECKPOINT-TACACS-ORIGINAL', 'key'],
  ['checkpoint JSON private key', '"private-key":"CHECKPOINT-PRIVATE-ORIGINAL"', 'CHECKPOINT-PRIVATE-ORIGINAL', 'certificate'],
  ['checkpoint text certificate key', 'certificate-key: CHECKPOINT-CERTIFICATE-ORIGINAL', 'CHECKPOINT-CERTIFICATE-ORIGINAL', 'certificate'],

  ['sonicwall shared secret', 'Shared Secret: SONICWALL-PSK-ORIGINAL', 'SONICWALL-PSK-ORIGINAL', 'key'],
  ['sonicwall password', 'Password: SONICWALL-PASSWORD-ORIGINAL', 'SONICWALL-PASSWORD-ORIGINAL', 'hash'],
  ['sonicwall password hash', 'Password Hash: SONICWALL-HASH-ORIGINAL', 'SONICWALL-HASH-ORIGINAL', 'hash'],
  ['sonicwall SNMP community', 'SNMP Community: SONICWALL-SNMP-ORIGINAL', 'SONICWALL-SNMP-ORIGINAL', 'community'],
  ['sonicwall RADIUS secret', 'RADIUS Secret: SONICWALL-RADIUS-ORIGINAL', 'SONICWALL-RADIUS-ORIGINAL', 'key'],
  ['sonicwall TACACS key', 'TACACS Key: SONICWALL-TACACS-ORIGINAL', 'SONICWALL-TACACS-ORIGINAL', 'key'],
  ['sonicwall private key', 'Private Key: SONICWALL-PRIVATE-ORIGINAL', 'SONICWALL-PRIVATE-ORIGINAL', 'certificate'],
  ['sonicwall certificate secret', 'Certificate Secret: SONICWALL-CERTIFICATE-ORIGINAL', 'SONICWALL-CERTIFICATE-ORIGINAL', 'certificate'],

  ['generic RSA private key', '-----BEGIN RSA PRIVATE KEY-----\nRSA-PRIVATE-KEY-ORIGINAL\n-----END RSA PRIVATE KEY-----', 'RSA-PRIVATE-KEY-ORIGINAL', 'certificate'],
  ['generic EC private key', '-----BEGIN EC PRIVATE KEY-----\nEC-PRIVATE-KEY-ORIGINAL\n-----END EC PRIVATE KEY-----', 'EC-PRIVATE-KEY-ORIGINAL', 'certificate'],
  ['generic DSA private key', '-----BEGIN DSA PRIVATE KEY-----\nDSA-PRIVATE-KEY-ORIGINAL\n-----END DSA PRIVATE KEY-----', 'DSA-PRIVATE-KEY-ORIGINAL', 'certificate'],
  ['generic encrypted PKCS8 private key', '-----BEGIN ENCRYPTED PRIVATE KEY-----\nENCRYPTED-PKCS8-ORIGINAL\n-----END ENCRYPTED PRIVATE KEY-----', 'ENCRYPTED-PKCS8-ORIGINAL', 'certificate'],
  ['generic unencrypted PKCS8 private key', '-----BEGIN PRIVATE KEY-----\nUNENCRYPTED-PKCS8-ORIGINAL\n-----END PRIVATE KEY-----', 'UNENCRYPTED-PKCS8-ORIGINAL', 'certificate'],
  ['generic OpenSSH private key', '-----BEGIN OPENSSH PRIVATE KEY-----\nOPENSSH-PRIVATE-KEY-ORIGINAL\n-----END OPENSSH PRIVATE KEY-----', 'OPENSSH-PRIVATE-KEY-ORIGINAL', 'certificate'],
];

const ACCEPTANCE_SECRET_MATRIX = [
  ['PSK', 'set psksecret "ACCEPTANCE-PSK-ORIGINAL"', 'ACCEPTANCE-PSK-ORIGINAL'],
  ['SNMP', 'snmp-server community ACCEPTANCE-SNMP-ORIGINAL', 'ACCEPTANCE-SNMP-ORIGINAL'],
  ['password', 'set password "ACCEPTANCE-PASSWORD-ORIGINAL"', 'ACCEPTANCE-PASSWORD-ORIGINAL'],
  ['hash', 'enable secret ACCEPTANCE-HASH-ORIGINAL', 'ACCEPTANCE-HASH-ORIGINAL'],
  ['RADIUS', 'radius-server host 192.0.2.2 key ACCEPTANCE-RADIUS-ORIGINAL', 'ACCEPTANCE-RADIUS-ORIGINAL'],
  ['TACACS', 'set tacacs-secret "ACCEPTANCE-TACACS-ORIGINAL"', 'ACCEPTANCE-TACACS-ORIGINAL'],
  ['private key', '-----BEGIN PRIVATE KEY-----\nACCEPTANCE-PRIVATE-ORIGINAL\n-----END PRIVATE KEY-----', 'ACCEPTANCE-PRIVATE-ORIGINAL'],
  ['certificate secret', 'Certificate Secret: ACCEPTANCE-CERTIFICATE-ORIGINAL', 'ACCEPTANCE-CERTIFICATE-ORIGINAL'],
];

const FORTIGATE_MULTI_ENTRY_BLOCKS = [
  {
    label: 'TACACS keys',
    type: 'key',
    markers: [
      'FGT-TACACS-QUOTED-MULTI-1', 'FGT-TACACS-QUOTED-MULTI-2',
      'FGT-TACACS-BARE-MULTI-1', 'FGT-TACACS-BARE-MULTI-2',
      'FGT-TACACS-ENC-MULTI-1', 'FGT-TACACS-ENC-MULTI-2',
    ],
    text: `config user tacacs+
 edit "tac-quoted"
  set key "FGT-TACACS-QUOTED-MULTI-1"
 next
 edit "tac-quoted-2"
  set key "FGT-TACACS-QUOTED-MULTI-2"
 next
 edit "tac-bare"
  set key FGT-TACACS-BARE-MULTI-1
 next
 edit "tac-bare-2"
  set key FGT-TACACS-BARE-MULTI-2
 next
 edit "tac-enc"
  set key ENC "FGT-TACACS-ENC-MULTI-1"
 next
 edit "tac-enc-2"
  set key ENC "FGT-TACACS-ENC-MULTI-2"
 next
end`,
  },
  {
    label: 'SNMP community names',
    type: 'community',
    markers: [
      'FGT-SNMP-QUOTED-MULTI-1', 'FGT-SNMP-QUOTED-MULTI-2',
      'FGT-SNMP-BARE-MULTI-1', 'FGT-SNMP-BARE-MULTI-2',
      'FGT-SNMP-ENC-MULTI-1', 'FGT-SNMP-ENC-MULTI-2',
    ],
    text: `config system snmp community
 edit 1
  set name "FGT-SNMP-QUOTED-MULTI-1"
 next
 edit 11
  set name "FGT-SNMP-QUOTED-MULTI-2"
 next
 edit 2
  set name FGT-SNMP-BARE-MULTI-1
 next
 edit 22
  set name FGT-SNMP-BARE-MULTI-2
 next
 edit 3
  set name ENC "FGT-SNMP-ENC-MULTI-1"
 next
 edit 33
  set name ENC "FGT-SNMP-ENC-MULTI-2"
 next
end`,
  },
];

const FORTIGATE_NESTED_SNMP_BLOCK = `config system snmp community
 edit 1
  set name "FIRST-SNMP-SECRET"
  config hosts
   edit 1
    set ip 192.0.2.1 255.255.255.255
   next
  end
 next
 edit 2
  set name SECOND-SNMP-SECRET
 next
 edit 3
  set name ENC "THIRD-SNMP-SECRET"
 next
end`;

const INCOMPLETE_FORTIGATE_BLOCKS = [
  {
    label: 'SNMP outer scope',
    ruleId: 'fortigate-snmp-block-name',
    markers: ['SNMP-INCOMPLETE-QUOTED', 'SNMP-INCOMPLETE-BARE', 'SNMP-INCOMPLETE-ENC'],
    text: `config system snmp community
 edit 1
  set name "SNMP-INCOMPLETE-QUOTED"
 next
 edit 2
  set name SNMP-INCOMPLETE-BARE
 next
 edit 3
  set name ENC "SNMP-INCOMPLETE-ENC"
 next`,
  },
  {
    label: 'TACACS outer scope',
    ruleId: 'fortigate-tacacs-block-key',
    markers: ['TACACS-INCOMPLETE-QUOTED', 'TACACS-INCOMPLETE-BARE', 'TACACS-INCOMPLETE-ENC'],
    text: `config user tacacs+
 edit "one"
  set key "TACACS-INCOMPLETE-QUOTED"
 next
 edit "two"
  set key TACACS-INCOMPLETE-BARE
 next
 edit "three"
  set key ENC "TACACS-INCOMPLETE-ENC"
 next`,
  },
  {
    label: 'SNMP nested scope',
    ruleId: 'fortigate-snmp-block-name',
    markers: ['SNMP-NESTED-QUOTED', 'SNMP-NESTED-BARE', 'SNMP-NESTED-ENC'],
    text: `config system snmp community
 edit 1
  set name "SNMP-NESTED-QUOTED"
 next
 edit 2
  set name SNMP-NESTED-BARE
 next
 edit 3
  set name ENC "SNMP-NESTED-ENC"
 next
 config hosts
  edit 1
   set ip 192.0.2.1 255.255.255.255
  next`,
  },
  {
    label: 'TACACS nested scope',
    ruleId: 'fortigate-tacacs-block-key',
    markers: ['TACACS-NESTED-QUOTED', 'TACACS-NESTED-BARE', 'TACACS-NESTED-ENC'],
    text: `config user tacacs+
 edit "one"
  set key "TACACS-NESTED-QUOTED"
 next
 edit "two"
  set key TACACS-NESTED-BARE
 next
 edit "three"
  set key ENC "TACACS-NESTED-ENC"
 next
 config metadata
  edit "unfinished"
   set value "not-a-key"
  next`,
  },
];

const PLACEHOLDER_ONLY_INCOMPLETE_BLOCKS = [
  `config system snmp community
 edit 1
  set name SANITIZED_COMMUNITY_0
 next`,
  `config user tacacs+
 edit "one"
  set key SANITIZED_KEY_0
 next`,
  `config system snmp community
 config hosts
  edit 1
   set ip 192.0.2.1 255.255.255.255
  next`,
  `config user tacacs+
 config metadata
  edit "unfinished"
  next`,
];

const INCOMPLETE_SCOPE_ERROR = {
  name: 'SecretScopeError',
  code: 'incomplete_sensitive_scope',
  message: 'Sensitive FortiGate configuration block is incomplete.',
};

describe('firewall secret registry', () => {
  it.each(['\n', '\r\n', '\r'])(
    'preserves complete FortiGate block behavior with %j line endings',
    lineEnding => {
      const text = [
        'config system snmp community',
        ' edit 1',
        '  set name "COMPLETE-LINE-ENDING-SECRET"',
        ' next',
        'end',
      ].join(lineEnding);
      expect(findSecretsInText(text)).toEqual([{
        category: 'community',
        ruleId: 'fortigate-snmp-block-name',
      }]);
      const redacted = redactConfigSecrets(text);
      expect(redacted.replacements).toHaveLength(1);
      expect(redacted.text).not.toContain('COMPLETE-LINE-ENDING-SECRET');
      expect(redacted.text).toContain(lineEnding);
    },
  );

  it.each(INCOMPLETE_FORTIGATE_BLOCKS)(
    'scans every secret through EOF and reports malformed $label',
    ({ text, markers, ruleId }) => {
      const findings = findSecretsInText(text);
      expect(findings.filter(finding => finding.ruleId === ruleId)).toHaveLength(3);
      const scopeFindings = findings.filter(finding => (
        finding.ruleId === 'fortigate-incomplete-sensitive-block'
      ));
      expect(scopeFindings).toEqual([{
        category: 'scope',
        ruleId: 'fortigate-incomplete-sensitive-block',
      }]);
      for (const marker of markers) {
        expect(JSON.stringify(scopeFindings)).not.toContain(marker);
      }
    },
  );

  it.each(INCOMPLETE_FORTIGATE_BLOCKS)(
    'rejects redaction and sanitization of malformed $label with fixed local errors',
    ({ text, markers }) => {
      for (const operation of [redactConfigSecrets, sanitizeConfig]) {
        let error;
        try {
          operation(text);
        } catch (caught) {
          error = caught;
        }
        expect(error).toMatchObject(INCOMPLETE_SCOPE_ERROR);
        expect(error).not.toHaveProperty('cause');
        for (const marker of markers) expect(error.message).not.toContain(marker);
      }
    },
  );

  it.each(PLACEHOLDER_ONLY_INCOMPLETE_BLOCKS)(
    'fails closed for placeholder-only or empty incomplete sensitive block %#',
    text => {
      expect(findSecretsInText(text)).toEqual([{
        category: 'scope',
        ruleId: 'fortigate-incomplete-sensitive-block',
      }]);
      expect(() => redactConfigSecrets(text)).toThrow(
        expect.objectContaining(INCOMPLETE_SCOPE_ERROR),
      );
      expect(() => sanitizeConfig(text)).toThrow(
        expect.objectContaining(INCOMPLETE_SCOPE_ERROR),
      );
    },
  );

  it('keeps the complete nested FortiGate target block in secret scope', () => {
    const markers = [
      'FIRST-SNMP-SECRET',
      'SECOND-SNMP-SECRET',
      'THIRD-SNMP-SECRET',
    ];
    const findings = findSecretsInText(FORTIGATE_NESTED_SNMP_BLOCK);
    const redacted = redactConfigSecrets(FORTIGATE_NESTED_SNMP_BLOCK);
    const sanitized = sanitizeConfig(FORTIGATE_NESTED_SNMP_BLOCK);

    expect(findings).toHaveLength(3);
    expect(redacted.replacements).toHaveLength(3);
    expect(sanitized.replacements).toHaveLength(3);
    for (const marker of markers) {
      expect(redacted.text).not.toContain(marker);
      expect(sanitized.sanitizedText).not.toContain(marker);
      expect(redacted.replacements.some(entry => entry.original.includes(marker))).toBe(true);
    }
    for (const entry of redacted.replacements) {
      expect(entry).toEqual({
        type: 'community',
        placeholder: entry.placeholder,
        original: entry.original,
      });
      expect(redacted.text).toContain(entry.placeholder);
      expect(entry).not.toHaveProperty('restore');
    }
    expect(findSecretsInText(redacted.text)).toEqual([]);
    expect(redactConfigSecrets(redacted.text).replacements).toEqual([]);
  });

  it('scans multiple complete nested FortiGate target blocks', () => {
    const second = FORTIGATE_NESTED_SNMP_BLOCK
      .replaceAll('FIRST-SNMP-SECRET', 'FOURTH-SNMP-SECRET')
      .replaceAll('SECOND-SNMP-SECRET', 'FIFTH-SNMP-SECRET')
      .replaceAll('THIRD-SNMP-SECRET', 'SIXTH-SNMP-SECRET');
    const text = `${FORTIGATE_NESTED_SNMP_BLOCK}\n${second}`;
    const redacted = redactConfigSecrets(text);

    expect(findSecretsInText(text)).toHaveLength(6);
    expect(redacted.replacements.map(entry => entry.original)).toEqual([
      'FIRST-SNMP-SECRET',
      'SECOND-SNMP-SECRET',
      'ENC "THIRD-SNMP-SECRET"',
      'FOURTH-SNMP-SECRET',
      'FIFTH-SNMP-SECRET',
      'ENC "SIXTH-SNMP-SECRET"',
    ]);
  });

  it.each(FORTIGATE_MULTI_ENTRY_BLOCKS)(
    'enumerates and redacts every bounded FortiGate $label entry',
    ({ text, markers, type }) => {
      const findings = findSecretsInText(text);
      const redacted = redactConfigSecrets(text);
      const sanitized = sanitizeConfig(text);

      expect(findings).toHaveLength(6);
      expect(redacted.replacements).toHaveLength(6);
      expect(sanitized.replacements).toHaveLength(6);
      for (const marker of markers) {
        expect(redacted.text).not.toContain(marker);
        expect(sanitized.sanitizedText).not.toContain(marker);
        expect(redacted.replacements.some(entry => entry.original.includes(marker))).toBe(true);
      }
      expect(redacted.replacements).toEqual(redacted.replacements.map(entry => ({
        type,
        placeholder: entry.placeholder,
        original: entry.original,
      })));
      expect(new Set(redacted.replacements.map(entry => entry.placeholder))).toHaveProperty('size', 6);
      for (const entry of redacted.replacements) {
        expect(redacted.text).toContain(entry.placeholder);
        expect(entry).not.toHaveProperty('restore');
      }
      expect(findSecretsInText(redacted.text)).toEqual([]);
      expect(redactConfigSecrets(redacted.text).replacements).toEqual([]);
    },
  );

  it.each(ACCEPTANCE_SECRET_MATRIX)(
    'acceptance: redacts the %s secret matrix',
    (_label, text, original) => {
      const findings = findSecretsInText(text);
      const redacted = redactConfigSecrets(text);
      expect(findings).toHaveLength(1);
      expect(redacted.text).not.toContain(original);
      expect(redacted.replacements).toHaveLength(1);
      expect(findSecretsInText(redacted.text)).toEqual([]);
    },
  );

  it.each(CASES)('detects and redacts %s', (_label, text, original, type) => {
    const findings = findSecretsInText(text);
    const redacted = redactConfigSecrets(text);
    expect(findings).toHaveLength(1);
    expect(redacted.text).not.toContain(original);
    expect(redacted.replacements).toEqual([
      expect.objectContaining({ type }),
    ]);
    expect(redacted.replacements[0].original).toContain(original);
    expect(redacted.replacements[0]).not.toHaveProperty('restore');
    expect(findSecretsInText(redacted.text)).toEqual([]);
    expect(redactConfigSecrets(redacted.text).replacements).toEqual([]);
  });

  it('keeps detection and sanitizeConfig redaction in parity', () => {
    for (const [, text, original] of CASES) {
      const result = sanitizeConfig(text);
      expect(result.sanitizedText).not.toContain(original);
      expect(result.replacements.some(entry => (
        text.startsWith('-----BEGIN ')
          ? entry.original.includes(original)
          : entry.original === original
      ))).toBe(true);
    }
  });

  it.each([
    'SANITIZED_HASH_0',
    'SANITIZED_KEY_19',
    'SANITIZED_COMMUNITY_2',
    'SANITIZED_CERT_4',
  ])('recognizes placeholder %s', value => {
    expect(isSanitizedSecretValue(value)).toBe(true);
    expect(findSecretsInText('set password "' + value + '"')).toEqual([]);
  });

  it('allocates after existing placeholder indexes', () => {
    const result = redactConfigSecrets(
      'set psksecret "SANITIZED_KEY_19"\nset secret "NEW-ORIGINAL"',
    );
    expect(result.text).toContain('SANITIZED_KEY_19');
    expect(result.replacements[0].placeholder).toBe('SANITIZED_KEY_20');
  });

  it.each(['password', 'password_hash', 'pre-shared-key', 'psksecret', 'snmpCommunity', 'radius_secret', 'tacplus-key', 'privateKey', 'certificate-key'])(
    'recognizes secret-bearing key %s',
    key => expect(isSecretBearingKey(key)).toBe(true),
  );

  it.each([
    'set security ike proposal ike authentication-method pre-shared-keys',
    '<certificate>PUBLIC-CERTIFICATE-DATA</certificate>',
    'set applications application tacacs-plus protocol tcp',
    'config firewall policy\n edit 1\n  set key "NON-SECRET-POLICY-KEY"\n  set name "NON-SECRET-POLICY-NAME"\n next\nend',
    'config system interface\n edit "port1"\n  set name "NON-SECRET-INTERFACE-NAME"\n next\nend',
  ])('does not classify non-secret syntax: %s', text => {
    expect(findSecretsInText(text)).toEqual([]);
  });

  it('scans pathological hierarchical AAA input in bounded time', () => {
    const hostile = `radius-server !{{:;${' :;'.repeat(20000)}`;
    const started = Date.now();
    findSecretsInText(hostile);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it.each([
    'radius-server h { ; secret q; }',
    'radius-server h { port 1; ; secret q; }',
    'radius-server h {\n;secret q;}',
    'radius-server h {;secret q;}',
    'tacacs-server h { ; key "quoted secret"; }',
    'tacplus-server h { ; secret bare-secret; }',
  ])('redacts a hierarchical server secret after an empty statement: %s', text => {
    const findings = findSecretsInText(text);
    const redacted = redactConfigSecrets(text);
    expect(findings).toEqual([
      expect.objectContaining({ ruleId: 'aaa-secret-hierarchical', category: 'key' }),
    ]);
    expect(redacted.replacements).toEqual([
      expect.objectContaining({ type: 'key' }),
    ]);
    expect(redacted.text).not.toContain(redacted.replacements[0].original);
    expect(findSecretsInText(redacted.text)).toEqual([]);
  });

  it('scans hierarchical server blocks that contain empty statements in bounded time', () => {
    const inputs = [
      `radius-server h {${' ;'.repeat(20000)} secret q; }`,
      `radius-server h {${';'.repeat(20000)} secret q; }`,
    ];
    const started = Date.now();
    for (const input of inputs) {
      expect(findSecretsInText(input)).toEqual([
        expect.objectContaining({ ruleId: 'aaa-secret-hierarchical' }),
      ]);
    }
    expect(Date.now() - started).toBeLessThan(2000);
  });
});
