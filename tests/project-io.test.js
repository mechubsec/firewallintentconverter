import { describe, expect, it, vi } from 'vitest';

import {
  CURRENT_VERSION,
  buildProjectCore,
  buildProjectPayload,
  validateProjectFile,
  validateProjectStateCore,
} from '../public/utils/project-io.js';
import {
  PROJECT_SECURITY_MODES,
  MAX_PROJECT_PLAINTEXT_BYTES,
  ProjectSecurityError,
  classifyProjectSecurity,
  inspectProjectImport,
  openProjectImport,
  serializeProjectExport,
} from '../public/utils/project-security.js';
import { ConversionOutputError } from '../src/conversion/conversion-output.js';
import { parseCiscoAsaConfig } from '../src/parsers/cisco-asa-parser.js';
import { parseFortigateConfig } from '../src/parsers/fortigate-parser.js';
import { parsePanosConfig } from '../src/parsers/panos-parser.js';
import { sanitizeConfig } from '../public/utils/engine.js';
import { findSecretsInText } from '../public/utils/secret-detection.js';
import {
  ProjectCryptoError,
  encryptReversiblePayload,
} from '../public/utils/project-crypto.js';

const IDENTIFIER_MAPPINGS = { version: 1, entries: [] };
const RECONVERT_WARNING = 'Generated output from this older project was cleared because it has no validated identifier mapping. Reconvert before export or device push.';
const PASSPHRASE = 'correct horse battery staple';
const SANITIZED_SECURITY = {
  schema: 1,
  mode: 'sanitized',
  containsOriginals: false,
  reversible: false,
  restorationAvailable: false,
};

const baseState = {
  configText: 'set system host-name source',
  intermediateConfig: { metadata: {} },
};

function project(version, srxOutput, outputFormat = 'set', state = {}) {
  return {
    fpic_version: version,
    name: 'project',
    savedAt: '2026-07-11T00:00:00.000Z',
    state: { ...baseState, srxOutput, outputFormat, ...state },
  };
}

function restorationTable(original = 'ORIGINAL-FW') {
  return [{
    type: 'device_hostname',
    placeholder: 'sanitized-fw',
    original,
  }];
}

function reversiblePayload(state) {
  return {
    payloadSchema: 1,
    name: 'forged-authenticated-project',
    savedAt: '2026-07-11T00:00:00.000Z',
    sourceMode: 'sanitized',
    state,
  };
}

function v5Project(mode, state, overrides = {}) {
  const security = mode === 'sanitized'
    ? { ...SANITIZED_SECURITY }
    : {
      schema: 1,
      mode: 'unsanitized',
      containsOriginals: true,
      reversible: false,
      restorationAvailable: false,
    };
  return {
    fpic_version: 5,
    name: 'project',
    savedAt: '2026-07-11T00:00:00.000Z',
    security,
    state,
    ...overrides,
  };
}

function serializedAtUtf8Bytes(value, targetBytes) {
  const withEmptyPadding = JSON.stringify({
    ...value,
    state: { ...value.state, padding: '' },
  });
  const paddingLength = targetBytes - new TextEncoder().encode(withEmptyPadding).length;
  if (paddingLength < 0) throw new Error('fixture target is too small');
  return JSON.stringify({
    ...value,
    state: { ...value.state, padding: 'x'.repeat(paddingLength) },
  });
}

describe('version 5 project security formats', () => {
  it('fails closed at the legacy builder before live state can be serialized', () => {
    const sensitiveState = {
      ...baseState,
      configText: 'UNIQUE-LIVE-STATE-SENTINEL',
    };
    let payload;
    let error;
    try {
      payload = JSON.stringify(buildProjectPayload(sensitiveState, 'UNIQUE-PROJECT-NAME'));
    } catch (caught) {
      error = caught;
    }
    expect(payload).toBeUndefined();
    expect(error).toMatchObject({
      code: 'secure_export_required',
      message: 'Project export must use the secure export boundary.',
    });
    expect(error.message).not.toContain('UNIQUE-LIVE-STATE-SENTINEL');
    expect(error.message).not.toContain('UNIQUE-PROJECT-NAME');
  });

  it('acceptance: default sanitized export contains no originals or restoration table', async () => {
    const state = {
      ...baseState,
      isSanitized: true,
      sanitizationTable: restorationTable('UNIQUE-ORIGINAL-HOST'),
    };
    const result = await serializeProjectExport(state, 'safe project', { mode: 'sanitized' });
    const parsed = JSON.parse(result.serialized);
    expect(parsed).toMatchObject({
      fpic_version: 5,
      security: {
        mode: 'sanitized',
        containsOriginals: false,
        reversible: false,
        restorationAvailable: false,
      },
    });
    expect(result.filename).toBe('safe-project.sanitized.fpic.json');
    expect(result.serialized).not.toContain('UNIQUE-ORIGINAL-HOST');
    expect(result.serialized).not.toContain('sanitizationTable');
  });

  it('acceptance: unsanitized export requires exact typed confirmation', async () => {
    await expect(serializeProjectExport(baseState, 'unsafe', {
      mode: 'unsanitized',
      confirmation: '',
    })).rejects.toMatchObject({ code: 'invalid_confirmation' });
    await expect(serializeProjectExport(baseState, 'unsafe', {
      mode: 'unsanitized',
      confirmation: 'EXPORT UNSANITIZED',
    })).resolves.toMatchObject({
      filename: 'unsafe.unsanitized.fpic.json',
    });
  });

  it('writes exact plaintext unsanitized metadata after rescanning state', async () => {
    const result = await serializeProjectExport({
      ...baseState,
      isSanitized: false,
      sanitizationTable: restorationTable(),
    }, 'unsafe', {
      mode: 'unsanitized', confirmation: 'EXPORT UNSANITIZED',
    });
    const parsed = JSON.parse(result.serialized);
    expect(Object.keys(parsed)).toEqual(['fpic_version', 'name', 'savedAt', 'security', 'state']);
    expect(parsed.security).toEqual({
      schema: 1,
      mode: 'unsanitized',
      containsOriginals: true,
      reversible: false,
      restorationAvailable: true,
    });
    const opened = await openProjectImport(result.serialized, {});
    expect(opened).toMatchObject({
      security: parsed.security,
      requiresConfirmation: true,
    });
    expect(opened.project.state.sanitizationTable).toEqual(restorationTable());
  });

  it('computes unsanitized restoration metadata from final canonical state', async () => {
    const result = await serializeProjectExport({
      ...baseState,
      isSanitized: false,
      futureState: {
        sanitizationTable: restorationTable('DROPPED-FUTURE-ORIGINAL'),
      },
    }, 'future-state', {
      mode: 'unsanitized', confirmation: 'EXPORT UNSANITIZED',
    });
    const parsed = JSON.parse(result.serialized);
    expect(parsed.state).not.toHaveProperty('futureState');
    expect(parsed.state.sanitizationTable).toBeNull();
    expect(parsed.security.restorationAvailable).toBe(false);
  });

  it.each([
    ['missing acknowledgement', { confirmationPassphrase: PASSPHRASE }, 'invalid_confirmation'],
    ['missing confirmation', { acknowledgement: true }, 'invalid_confirmation'],
    ['mismatched confirmation', {
      acknowledgement: true, confirmationPassphrase: 'correct horse battery stapler',
    }, 'invalid_confirmation'],
    ['missing encryption passphrase', {
      acknowledgement: true, passphrase: undefined, confirmationPassphrase: undefined,
    }, 'invalid_passphrase'],
  ])('acceptance: reversible export requires passphrase confirmation and acknowledgement: %s', async (_label, options, code) => {
    const state = {
      ...baseState,
      isSanitized: true,
      sanitizationTable: restorationTable(),
    };
    await expect(serializeProjectExport(state, 'backup', {
      mode: 'reversible-encrypted',
      passphrase: PASSPHRASE,
      ...options,
    })).rejects.toMatchObject({ code });
  });

  it('acceptance: reversible export is encrypted and authenticated', async () => {
    const exported = await serializeProjectExport({
      ...baseState,
      isSanitized: true,
      sanitizationTable: restorationTable('ENCRYPTED-ORIGINAL-FW'),
    }, 'encrypted backup', {
      mode: PROJECT_SECURITY_MODES.REVERSIBLE,
      passphrase: PASSPHRASE,
      confirmationPassphrase: PASSPHRASE,
      acknowledgement: true,
    });
    expect(exported.filename).toBe('encrypted-backup.reversible.fpic.enc.json');
    expect(exported.serialized).not.toContain('ENCRYPTED-ORIGINAL-FW');
    const inspected = inspectProjectImport(exported.serialized);
    expect(inspected).toMatchObject({
      kind: 'reversible-encrypted',
      security: { mode: 'reversible-encrypted' },
    });
    const opened = await openProjectImport(exported.serialized, { passphrase: PASSPHRASE });
    expect(opened).toMatchObject({
      security: { mode: 'reversible-encrypted' },
      requiresConfirmation: true,
      project: { fpic_version: 5, name: 'encrypted backup' },
    });
    expect(opened.project.state.sanitizationTable).toEqual(
      restorationTable('ENCRYPTED-ORIGINAL-FW'),
    );
  });

  it.each([
    ['unsanitized source claim', {
      ...baseState,
      configText: 'set password "FORGED-RAW-PASSWORD"',
      isSanitized: false,
      sanitizationTable: null,
    }],
    ['missing reversible restoration data', {
      ...baseState,
      configText: 'set system host-name sanitized-fw',
      isSanitized: true,
      sanitizationTable: null,
    }],
    ['residual secret-bearing candidate state', {
      ...baseState,
      configText: 'set system host-name SANITIZED_HOST_0',
      isSanitized: true,
      sanitizationTable: restorationTable('FORGED-ORIGINAL-HOST'),
      futureState: { warning: 'set password "FORGED-RESIDUAL-PASSWORD"' },
    }],
  ])('rejects authenticated reversible payload with %s', async (_label, state) => {
    const envelope = await encryptReversiblePayload(reversiblePayload(state), PASSPHRASE);
    let error;
    try {
      await openProjectImport(JSON.stringify(envelope), { passphrase: PASSPHRASE });
    } catch (caught) {
      error = caught;
    }
    expect(error).toMatchObject({
      name: 'ProjectCryptoError',
      code: 'decryption_failed',
      message: 'Encrypted project could not be opened.',
    });
    expect(error).not.toHaveProperty('cause');
  });

  it('normalizes every recognized encrypted-file open failure at the real import boundary', async () => {
    const exported = await serializeProjectExport({
      ...baseState,
      configText: 'set system host-name SANITIZED_HOST_0',
      isSanitized: true,
      sanitizationTable: restorationTable('UNIFORM-OPEN-ORIGINAL'),
    }, 'uniform-open-errors', {
      mode: PROJECT_SECURITY_MODES.REVERSIBLE,
      passphrase: PASSPHRASE,
      confirmationPassphrase: PASSPHRASE,
      acknowledgement: true,
    });
    const originalEnvelope = JSON.parse(exported.serialized);
    const cases = [
      ['short wrong passphrase', () => structuredClone(originalEnvelope), 'short'],
      ['altered fixed metadata', envelope => {
        envelope.security.schema = 2;
        return envelope;
      }, PASSPHRASE],
      ['altered salt', envelope => {
        envelope.security.salt = (envelope.security.salt[0] === 'A' ? 'B' : 'A')
          + envelope.security.salt.slice(1);
        return envelope;
      }, PASSPHRASE],
      ['altered nonce', envelope => {
        envelope.security.nonce = (envelope.security.nonce[0] === 'A' ? 'B' : 'A')
          + envelope.security.nonce.slice(1);
        return envelope;
      }, PASSPHRASE],
      ['altered ciphertext', envelope => {
        envelope.ciphertext = (envelope.ciphertext[0] === 'A' ? 'B' : 'A')
          + envelope.ciphertext.slice(1);
        return envelope;
      }, PASSPHRASE],
    ];

    for (const [label, mutate, passphrase] of cases) {
      const envelope = mutate(structuredClone(originalEnvelope));
      let error;
      try {
        await openProjectImport(JSON.stringify(envelope), { passphrase });
      } catch (caught) {
        error = caught;
      }
      expect(error, label).toMatchObject({
        name: 'ProjectCryptoError',
        code: 'decryption_failed',
        message: 'Encrypted project could not be opened.',
      });
      expect(error, label).not.toHaveProperty('cause');
      expect(Reflect.ownKeys(error).filter(key => ![
        'stack', 'message', 'name', 'code',
      ].includes(key)), label).toEqual([]);
      expect(error.message, label).not.toContain('UNIFORM-OPEN-ORIGINAL');
      expect(error.message, label).not.toContain(passphrase);
    }
  });

  it('normalizes altered recognized encrypted metadata during initial inspection', async () => {
    const exported = await serializeProjectExport({
      ...baseState,
      configText: 'set system host-name SANITIZED_HOST_0',
      isSanitized: true,
      sanitizationTable: restorationTable('INSPECTION-ORIGINAL'),
    }, 'inspection-errors', {
      mode: PROJECT_SECURITY_MODES.REVERSIBLE,
      passphrase: PASSPHRASE,
      confirmationPassphrase: PASSPHRASE,
      acknowledgement: true,
    });
    const envelope = JSON.parse(exported.serialized);
    envelope.security.schema = 2;

    let error;
    try {
      inspectProjectImport(JSON.stringify(envelope));
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(ProjectCryptoError);
    expect(error).toMatchObject({
      name: 'ProjectCryptoError',
      code: 'decryption_failed',
      message: 'Encrypted project could not be opened.',
    });
    expect(error).not.toHaveProperty('cause');
    expect(Reflect.ownKeys(error).filter(key => ![
      'stack', 'message', 'name', 'code',
    ].includes(key))).toEqual([]);
    expect(error.message).not.toContain('INSPECTION-ORIGINAL');

    const plaintext = JSON.parse(exported.serialized);
    plaintext.security.mode = PROJECT_SECURITY_MODES.SANITIZED;
    expect(() => inspectProjectImport(JSON.stringify(plaintext))).toThrow(
      expect.objectContaining({
        name: ProjectSecurityError.name,
        code: 'invalid_project',
        message: 'Project file is invalid.',
      }),
    );
  });

  it('acceptance: sanitized import cannot restore originals', async () => {
    const exported = await serializeProjectExport({
      ...baseState,
      isSanitized: true,
      sanitizationTable: [{
        type: 'key', placeholder: 'SANITIZED_KEY_0', original: 'IMPORT-ORIGINAL',
      }],
    }, 'safe', { mode: 'sanitized' });
    const opened = await openProjectImport(exported.serialized, {});
    expect(opened.security.mode).toBe('sanitized');
    expect(opened.security.restorationAvailable).toBe(false);
    expect(opened.requiresConfirmation).toBe(false);
    expect(opened.project.state.sanitizationTable).toBeNull();
    expect(JSON.stringify(opened.project)).not.toContain('IMPORT-ORIGINAL');
  });

  const PARSER_SECRET_CASES = [
    {
      label: 'ASA SNMP host community',
      original: 'ASA-HOST-COMM-SECRET',
      text: 'ASA Version 9.18\nsnmp-server host inside 192.0.2.44 community ASA-HOST-COMM-SECRET version 2c',
      parse: value => parseCiscoAsaConfig(value),
    },
    {
      label: 'FortiGate TACACS block key',
      original: 'FGT-TACACS-REAL-SECRET',
      text: 'config user tacacs+\n edit "tac-1"\n  set server "192.0.2.10"\n  set key "FGT-TACACS-REAL-SECRET"\n next\nend',
      parse: value => parseFortigateConfig(value),
    },
    {
      label: 'FortiGate SNMP block name',
      original: 'FGT-SNMP-REAL-SECRET',
      text: 'config system snmp community\n edit 1\n  set name "FGT-SNMP-REAL-SECRET"\n next\nend',
      parse: value => parseFortigateConfig(value),
    },
    {
      label: 'PAN-OS direct RADIUS secret',
      original: 'PANOS-RADIUS-REAL-SECRET',
      text: '<config version="11.1"><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><authentication-profile><entry name="rad"><method><radius><server-profile>r</server-profile><secret>PANOS-RADIUS-REAL-SECRET</secret></radius></method></entry></authentication-profile></entry></vsys></entry></devices></config>',
      parse: value => parsePanosConfig(value),
    },
  ];

  const FORTIGATE_MULTI_ENTRY_EXPORT_CASES = [
    {
      label: 'TACACS keys',
      markers: [
        'FGT-TACACS-QUOTED-EXPORT-1', 'FGT-TACACS-QUOTED-EXPORT-2',
        'FGT-TACACS-BARE-EXPORT-1', 'FGT-TACACS-BARE-EXPORT-2',
        'FGT-TACACS-ENC-EXPORT-1', 'FGT-TACACS-ENC-EXPORT-2',
      ],
      text: `config user tacacs+
 edit "tac-quoted"
  set key "FGT-TACACS-QUOTED-EXPORT-1"
 next
 edit "tac-quoted-2"
  set key "FGT-TACACS-QUOTED-EXPORT-2"
 next
 edit "tac-bare"
  set key FGT-TACACS-BARE-EXPORT-1
 next
 edit "tac-bare-2"
  set key FGT-TACACS-BARE-EXPORT-2
 next
 edit "tac-enc"
  set key ENC "FGT-TACACS-ENC-EXPORT-1"
 next
 edit "tac-enc-2"
  set key ENC "FGT-TACACS-ENC-EXPORT-2"
 next
end`,
    },
    {
      label: 'SNMP community names',
      markers: [
        'FGT-SNMP-QUOTED-EXPORT-1', 'FGT-SNMP-QUOTED-EXPORT-2',
        'FGT-SNMP-BARE-EXPORT-1', 'FGT-SNMP-BARE-EXPORT-2',
        'FGT-SNMP-ENC-EXPORT-1', 'FGT-SNMP-ENC-EXPORT-2',
      ],
      text: `config system snmp community
 edit 1
  set name "FGT-SNMP-QUOTED-EXPORT-1"
 next
 edit 11
  set name "FGT-SNMP-QUOTED-EXPORT-2"
 next
 edit 2
  set name FGT-SNMP-BARE-EXPORT-1
 next
 edit 22
  set name FGT-SNMP-BARE-EXPORT-2
 next
 edit 3
  set name ENC "FGT-SNMP-ENC-EXPORT-1"
 next
 edit 33
  set name ENC "FGT-SNMP-ENC-EXPORT-2"
 next
end`,
    },
  ];

  const FORTIGATE_NESTED_SNMP_EXPORT = {
    markers: ['FIRST-SNMP-EXPORT', 'SECOND-SNMP-EXPORT', 'THIRD-SNMP-EXPORT'],
    text: `config system snmp community
 edit 1
  set name "FIRST-SNMP-EXPORT"
  config hosts
   edit 1
    set ip 192.0.2.1 255.255.255.255
   next
  end
 next
 edit 2
  set name SECOND-SNMP-EXPORT
 next
 edit 3
  set name ENC "THIRD-SNMP-EXPORT"
 next
end`,
  };

  const INCOMPLETE_FORTIGATE_EXPORTS = [
    {
      label: 'raw SNMP outer scope',
      text: `config system snmp community
 edit 1
  set name "FORGED-SNMP-QUOTED"
 next
 edit 2
  set name FORGED-SNMP-BARE
 next
 edit 3
  set name ENC "FORGED-SNMP-ENC"
 next`,
    },
    {
      label: 'raw TACACS nested scope',
      text: `config user tacacs+
 edit "one"
  set key "FORGED-TACACS-QUOTED"
 next
 edit "two"
  set key FORGED-TACACS-BARE
 next
 edit "three"
  set key ENC "FORGED-TACACS-ENC"
 next
 config metadata
  edit "unfinished"
  next`,
    },
    {
      label: 'placeholder-only SNMP nested scope',
      text: `config system snmp community
 edit 1
  set name SANITIZED_COMMUNITY_0
 next
 config hosts
  edit 1
   set ip 192.0.2.1 255.255.255.255
  next`,
    },
    {
      label: 'placeholder-only TACACS outer scope',
      text: `config user tacacs+
 edit "one"
  set key SANITIZED_KEY_0
 next`,
    },
  ];

  it.each(INCOMPLETE_FORTIGATE_EXPORTS)(
    'rejects forged sanitized export with incomplete $label',
    async ({ text }) => {
      await expect(serializeProjectExport({
        ...baseState,
        configText: text,
        isSanitized: true,
        sanitizationTable: null,
      }, 'forged-incomplete-fortigate', { mode: 'sanitized' }))
        .rejects.toMatchObject({
          code: 'secret_leak',
          message: 'Sanitized export was blocked because secret-bearing content remains.',
        });
    },
  );

  it('keeps every nested FortiGate SNMP marker out of sanitized final bytes', async () => {
    const { text, markers } = FORTIGATE_NESTED_SNMP_EXPORT;
    expect(findSecretsInText(text)).toHaveLength(3);
    await expect(serializeProjectExport({
      ...baseState,
      configText: text,
      isSanitized: true,
      sanitizationTable: null,
    }, 'unsafe-nested-snmp', { mode: 'sanitized' }))
      .rejects.toMatchObject({ code: 'secret_leak' });

    const sanitized = sanitizeConfig(text);
    expect(sanitized.replacements).toHaveLength(3);
    const parsed = parseFortigateConfig(sanitized.sanitizedText);
    expect(parsed.intermediateConfig).toBeDefined();
    const result = await serializeProjectExport({
      ...baseState,
      configText: sanitized.sanitizedText,
      intermediateConfig: parsed.intermediateConfig,
      isSanitized: true,
      sanitizationTable: sanitized.replacements,
    }, 'safe-nested-snmp', { mode: 'sanitized' });

    for (const marker of markers) expect(result.serialized).not.toContain(marker);
    for (const entry of sanitized.replacements) {
      expect(result.serialized).toContain(entry.placeholder);
      expect(entry).not.toHaveProperty('restore');
    }
    expect(result.serialized).not.toContain('sanitizationTable');
  });

  it.each(FORTIGATE_MULTI_ENTRY_EXPORT_CASES)(
    'keeps every multi-entry FortiGate $label marker out of sanitized final bytes',
    async ({ text, markers }) => {
      await expect(serializeProjectExport({
        ...baseState,
        configText: text,
        isSanitized: true,
        sanitizationTable: null,
      }, 'unsafe-multi-entry', { mode: 'sanitized' }))
        .rejects.toMatchObject({ code: 'secret_leak' });

      const sanitized = sanitizeConfig(text);
      expect(sanitized.replacements).toHaveLength(6);
      const parsed = parseFortigateConfig(sanitized.sanitizedText);
      const result = await serializeProjectExport({
        ...baseState,
        configText: sanitized.sanitizedText,
        intermediateConfig: parsed.intermediateConfig,
        isSanitized: true,
        sanitizationTable: sanitized.replacements,
      }, 'safe-multi-entry', { mode: 'sanitized' });

      for (const marker of markers) expect(result.serialized).not.toContain(marker);
      for (const entry of sanitized.replacements) {
        expect(result.serialized).toContain(entry.placeholder);
        expect(entry).not.toHaveProperty('restore');
      }
      expect(result.serialized).not.toContain('sanitizationTable');
    },
  );

  it.each(PARSER_SECRET_CASES)('rejects raw parser-supported secret syntax from sanitized export: $label', async ({ text }) => {
    await expect(serializeProjectExport({
      ...baseState,
      configText: text,
      isSanitized: true,
      sanitizationTable: null,
    }, 'unsafe-parser-input', { mode: 'sanitized' }))
      .rejects.toMatchObject({ code: 'secret_leak' });
  });

  it.each(PARSER_SECRET_CASES)('sanitizes parser-supported secret syntax before parsed export: $label', async ({ text, original, parse }) => {
    const sanitized = sanitizeConfig(text);
    const parsed = parse(sanitized.sanitizedText);
    const result = await serializeProjectExport({
      ...baseState,
      configText: sanitized.sanitizedText,
      intermediateConfig: parsed.intermediateConfig,
      isSanitized: true,
      sanitizationTable: sanitized.replacements,
    }, 'safe-parser-input', { mode: 'sanitized' });
    expect(result.serialized).not.toContain(original);
    expect(result.serialized).not.toContain('sanitizationTable');
  });

  it('does not preserve an ASA SNMP host community as a trap-group name', () => {
    const parsed = parseCiscoAsaConfig(
      'ASA Version 9.18\nsnmp-server host inside 192.0.2.44 community ASA-HOST-COMM-SECRET version 2c',
    );
    expect(JSON.stringify(parsed.intermediateConfig.snmp_config))
      .not.toContain('ASA-HOST-COMM-SECRET');
  });

  it('classifies mixed merge slots and populated greenfield state as unsanitized', async () => {
    const mixed = {
      ...baseState,
      isSanitized: true,
      sanitizationTable: restorationTable(),
      mergeMode: true,
      configSlots: [{
        configText: 'set system host-name raw-slot',
        intermediateConfig: { metadata: {} },
        isSanitized: false,
      }],
    };
    await expect(serializeProjectExport(mixed, 'mixed', { mode: 'sanitized' }))
      .rejects.toMatchObject({ code: 'unsanitized_source' });

    const greenfield = {
      configText: '',
      intermediateConfig: null,
      greenfieldMode: true,
      greenfieldTemplate: { hostname: 'generated' },
      isSanitized: true,
    };
    await expect(serializeProjectExport(greenfield, 'greenfield', { mode: 'sanitized' }))
      .rejects.toMatchObject({ code: 'unsanitized_source' });
  });

  it.each([
    ['unknown outer key', value => { value.extra = true; }, 'invalid_project'],
    ['unknown security key', value => { value.security.extra = true; }, 'invalid_project'],
    ['wrong sanitized claim', value => { value.security.containsOriginals = true; }, 'invalid_project'],
    ['wrong unsanitized claim', value => { value.security.containsOriginals = false; }, 'invalid_project'],
    ['unmatched restoration claim', value => { value.security.restorationAvailable = true; }, 'invalid_project'],
    ['recognized reversible outer shape', value => {
      value.security.mode = 'reversible-encrypted';
    }, 'decryption_failed'],
  ])('rejects malformed or cross-mode v5 metadata: %s', (_label, mutate, code) => {
    const value = v5Project('sanitized', {
      ...baseState,
      isSanitized: true,
    });
    if (_label.includes('unsanitized') || _label.includes('restoration')) {
      value.security = {
        schema: 1, mode: 'unsanitized', containsOriginals: true,
        reversible: false, restorationAvailable: false,
      };
      value.state.isSanitized = false;
    }
    mutate(value);
    expect(() => inspectProjectImport(JSON.stringify(value))).toThrow(expect.objectContaining({
      code,
    }));
  });

  it('rejects nested restoration fields and unproven populated sources in sanitized v5 files', () => {
    const nested = v5Project('sanitized', {
      ...baseState,
      isSanitized: true,
      future: { sanitizationTable: null },
    });
    expect(() => inspectProjectImport(JSON.stringify(nested))).toThrow(expect.objectContaining({
      code: 'invalid_project',
    }));

    const unproven = v5Project('sanitized', {
      ...baseState,
      isSanitized: false,
    });
    expect(() => inspectProjectImport(JSON.stringify(unproven))).toThrow(expect.objectContaining({
      code: 'invalid_project',
    }));
  });

  it('acceptance: legacy plaintext restoration tables are warned as secret-bearing', async () => {
    for (const version of [1, 2, 3, 4]) {
      const serialized = JSON.stringify(project(version, null, 'set', {
        isSanitized: true,
        sanitizationTable: restorationTable(`LEGACY-${version}`),
      }));
      expect(inspectProjectImport(serialized)).toMatchObject({
        kind: 'legacy-secret-bearing',
        security: { mode: 'legacy-secret-bearing', restorationAvailable: true },
      });
      await expect(openProjectImport(serialized, {})).resolves.toMatchObject({
        security: { mode: 'legacy-secret-bearing' },
        requiresConfirmation: true,
        project: { fpic_version: 5 },
      });
    }
  });

  it.each([1, 2, 3, 4])(
    'downgrades legacy v%s claimed-sanitized mixed merge state to confirmed unsanitized',
    version => {
      const serialized = JSON.stringify(project(version, null, 'set', {
        isSanitized: true,
        sanitizationTable: null,
        mergeMode: true,
        configSlots: [{
          configText: 'set system host-name raw-merge-slot',
          intermediateConfig: { metadata: {} },
          isSanitized: false,
          sanitizationTable: null,
        }],
      }));
      expect(inspectProjectImport(serialized)).toMatchObject({
        kind: PROJECT_SECURITY_MODES.UNSANITIZED,
        security: {
          mode: PROJECT_SECURITY_MODES.UNSANITIZED,
          restorationAvailable: false,
        },
        requiresConfirmation: true,
      });
    },
  );

  it.each([1, 2, 3, 4])(
    'downgrades legacy v%s claimed-sanitized residual secret syntax to confirmed unsanitized',
    version => {
      const serialized = JSON.stringify(project(version, null, 'set', {
        configText: 'set password "RAW-LEGACY-SECRET"',
        isSanitized: true,
        sanitizationTable: null,
      }));
      expect(inspectProjectImport(serialized)).toMatchObject({
        kind: PROJECT_SECURITY_MODES.UNSANITIZED,
        security: {
          mode: PROJECT_SECURITY_MODES.UNSANITIZED,
          restorationAvailable: false,
        },
        requiresConfirmation: true,
      });
    },
  );

  it('still rejects invalid restoration data in a legacy claimed-sanitized file', () => {
    const serialized = JSON.stringify(project(4, null, 'set', {
      isSanitized: true,
      sanitizationTable: [{
        type: 'key', placeholder: 'SANITIZED_KEY_0', original: '',
      }],
    }));
    expect(() => inspectProjectImport(serialized)).toThrow(expect.objectContaining({
      code: 'invalid_project',
    }));
  });

  it('rescans legacy sanitized projects without tables before classifying them safe', async () => {
    const safe = JSON.stringify(project(4, null, 'set', {
      configText: 'set system host-name sanitized-fw',
      isSanitized: true,
      sanitizationTable: null,
    }));
    expect(inspectProjectImport(safe)).toMatchObject({
      kind: 'sanitized', security: { mode: 'sanitized' },
    });
    const opened = await openProjectImport(safe, {});
    expect(opened.requiresConfirmation).toBe(false);
    expect(opened.project.state.sanitizationTable).toBeNull();

    const unsafe = JSON.stringify(project(4, null, 'set', {
      configText: 'set password "RAW-LEGACY-SECRET"',
      isSanitized: true,
      sanitizationTable: null,
    }));
    expect(inspectProjectImport(unsafe)).toMatchObject({
      kind: PROJECT_SECURITY_MODES.UNSANITIZED,
      requiresConfirmation: true,
    });
  });

  it('acceptance: keeps passphrases and secrets out of descriptors, errors, storage, and logs', async () => {
    const original = 'RETURNED-DESCRIPTOR-ORIGINAL';
    const passphrase = 'RETURNED-DESCRIPTOR-PASSPHRASE';
    const storage = {
      getItem: vi.fn(),
      removeItem: vi.fn(),
      setItem: vi.fn(),
    };
    const storageDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
    const logSpies = ['debug', 'error', 'info', 'log', 'warn']
      .map(method => vi.spyOn(console, method).mockImplementation(() => {}));
    let logCallCounts;
    let descriptor;
    let inspected;
    let exported;
    let wrongPassphraseError;
    try {
      Object.defineProperty(globalThis, 'localStorage', {
        configurable: true,
        value: storage,
      });
      const state = {
        ...baseState,
        isSanitized: true,
        sanitizationTable: restorationTable(original),
      };
      descriptor = classifyProjectSecurity(state);
      exported = await serializeProjectExport(state, 'private', {
        mode: PROJECT_SECURITY_MODES.REVERSIBLE,
        passphrase,
        confirmationPassphrase: passphrase,
        acknowledgement: true,
      });
      inspected = inspectProjectImport(exported.serialized);
      try {
        await openProjectImport(exported.serialized, { passphrase: 'wrong passphrase value' });
      } catch (error) {
        wrongPassphraseError = error;
      }
    } finally {
      logCallCounts = logSpies.map(spy => spy.mock.calls.length);
      for (const spy of logSpies) spy.mockRestore();
      if (storageDescriptor) {
        Object.defineProperty(globalThis, 'localStorage', storageDescriptor);
      } else {
        delete globalThis.localStorage;
      }
    }

    const observable = JSON.stringify({
      descriptor,
      inspected,
      exported,
      error: {
        code: wrongPassphraseError?.code,
        message: wrongPassphraseError?.message,
      },
    });
    expect(observable).not.toContain(original);
    expect(observable).not.toContain(passphrase);
    expect(wrongPassphraseError).toMatchObject({
      code: 'decryption_failed',
      message: 'Encrypted project could not be opened.',
    });
    expect(storage.getItem).not.toHaveBeenCalled();
    expect(storage.setItem).not.toHaveBeenCalled();
    expect(storage.removeItem).not.toHaveBeenCalled();
    expect(logCallCounts).toEqual([0, 0, 0, 0, 0]);
  });

  it('rejects unsupported versions with a fixed failure', () => {
    expect(() => inspectProjectImport(JSON.stringify({ fpic_version: 6 }))).toThrow(
      expect.objectContaining({
        code: 'unsupported_version',
        message: 'Project file version is not supported.',
      }),
    );
  });

  it.each([
    ['v5 unsanitized', () => v5Project('unsanitized', {
      ...baseState,
      isSanitized: false,
      sanitizationTable: null,
    })],
    ['legacy plaintext', () => project(4, null, 'set', {
      isSanitized: false,
      sanitizationTable: null,
    })],
  ])('enforces the 48 MiB plaintext import boundary for %s', (_label, createValue) => {
    const below = serializedAtUtf8Bytes(
      createValue(),
      MAX_PROJECT_PLAINTEXT_BYTES - 1,
    );
    const above = serializedAtUtf8Bytes(
      createValue(),
      MAX_PROJECT_PLAINTEXT_BYTES + 1,
    );
    expect(new TextEncoder().encode(below)).toHaveLength(MAX_PROJECT_PLAINTEXT_BYTES - 1);
    expect(new TextEncoder().encode(above)).toHaveLength(MAX_PROJECT_PLAINTEXT_BYTES + 1);
    expect(inspectProjectImport(below).kind).toBe(PROJECT_SECURITY_MODES.UNSANITIZED);

    let error;
    try {
      inspectProjectImport(above);
    } catch (caught) {
      error = caught;
    }
    expect(error).toMatchObject({
      code: 'oversized_project',
      message: 'Project data exceeds the supported size limit.',
    });
    expect(error.message).not.toContain('x'.repeat(64));
  });
});

describe('canonical project output', () => {
  it('builds version 5 project cores with canonical output', () => {
    const payload = buildProjectCore({
      ...baseState,
      srxOutput: {
        format: 'set',
        commands: ['set system host-name edge-1'],
        identifierMappings: IDENTIFIER_MAPPINGS,
      },
      outputFormat: 'set',
    }, 'canonical', SANITIZED_SECURITY);

    expect(CURRENT_VERSION).toBe(5);
    expect(payload.fpic_version).toBe(5);
    expect(payload.security).toEqual(SANITIZED_SECURITY);
    expect(payload.state.srxOutput).toEqual({
      format: 'set',
      commands: ['set system host-name edge-1'],
      identifierMappings: IDENTIFIER_MAPPINGS,
    });
  });

  it('round-trips version 5 mapping-bearing output through core validation', () => {
    const payload = buildProjectCore({
      ...baseState,
      srxOutput: {
        format: 'set',
        commands: ['set system host-name edge-1'],
        identifierMappings: IDENTIFIER_MAPPINGS,
      },
    }, 'round-trip', SANITIZED_SECURITY);
    const result = validateProjectStateCore(JSON.parse(JSON.stringify(payload)));

    expect(result.project).toMatchObject({
      fpic_version: 5,
      name: 'round-trip',
      state: {
        outputFormat: 'set',
        srxOutput: {
          format: 'set',
          commands: ['set system host-name edge-1'],
          identifierMappings: IDENTIFIER_MAPPINGS,
        },
      },
    });
    expect(Object.isFrozen(result.project.state.srxOutput.identifierMappings)).toBe(true);
    expect(result.warnings).toEqual([]);
  });

  it('rejects invalid output at the new-project core boundary', () => {
    for (const srxOutput of [
      'set system host-name legacy',
      { commands: ['set system host-name legacy-object'], identifierMappings: IDENTIFIER_MAPPINGS },
      { srxCommands: 'set system host-name bypass', identifierMappings: IDENTIFIER_MAPPINGS },
    ]) {
      expect(() => buildProjectCore({ ...baseState, srxOutput }, 'invalid', SANITIZED_SECURITY))
        .toThrow(ConversionOutputError);
    }
  });

  it('corrects a stale output format when building canonical Set Commands output', () => {
    const payload = buildProjectCore({
      ...baseState,
      srxOutput: {
        format: 'set',
        commands: ['set system host-name edge-1'],
        identifierMappings: IDENTIFIER_MAPPINGS,
      },
      outputFormat: 'xml',
    }, 'stale-format', SANITIZED_SECURITY);
    expect(payload.state.outputFormat).toBe('set');
  });

  it('clears unmapped legacy artifacts but preserves editable state', () => {
    const result = validateProjectFile(project(3, {
      format: 'set',
      commands: ['set system host-name edge'],
    }, 'set', {
      convertWarnings: [{ type: 'warning' }],
      conversionSummary: { policies_converted: 1 },
      sourceVendor: 'fortigate',
      targetModel: 'srx1600',
      parseWarnings: [{ type: 'parser-warning' }],
    }));

    expect(result.valid).toBe(true);
    expect(result.project.fpic_version).toBe(5);
    expect(result.project.state.intermediateConfig).toEqual(baseState.intermediateConfig);
    expect(result.project.state.configText).toBe(baseState.configText);
    expect(result.project.state.sourceVendor).toBe('fortigate');
    expect(result.project.state.targetModel).toBe('srx1600');
    expect(result.project.state.parseWarnings).toEqual([{ type: 'parser-warning' }]);
    expect(result.project.state.outputFormat).toBe('set');
    expect(result.project.state.srxOutput).toBeNull();
    expect(result.project.state.convertWarnings).toEqual([]);
    expect(result.project.state.conversionSummary).toBeNull();
    expect(result.warnings).toEqual([RECONVERT_WARNING]);
  });

  it('migrates mapped conversion output through secure legacy import', async () => {
    const legacy = project(2, {
      commands: ['set system host-name edge-2'],
      warnings: [],
      identifierMappings: IDENTIFIER_MAPPINGS,
    }, 'set', { isSanitized: false });
    const opened = await openProjectImport(JSON.stringify(legacy), {});
    expect(opened.project.fpic_version).toBe(5);
    expect(opened.project.state.srxOutput).toEqual({
      format: 'set',
      commands: ['set system host-name edge-2'],
      warnings: [],
      identifierMappings: IDENTIFIER_MAPPINGS,
    });
    expect(opened.warnings).toEqual([]);
  });

  it('rejects malformed mapped and current conversion output without reflecting details', () => {
    const malformed = validateProjectFile(project(3, {
      commands: ['set system host-name edge-1'],
      identifierMappings: { version: 2, entries: [] },
    }));
    expect(malformed.valid).toBe(false);
    expect(malformed.error).toMatch(/identifier mapping/i);

    const missing = validateProjectFile(project(5, {
      format: 'set', commands: ['set system host-name edge-1'],
    }));
    expect(missing.valid).toBe(false);
    expect(missing.error).toMatch(/identifier mapping/i);

    const invalid = validateProjectFile(project(5, {
      format: 'set',
      commands: ['set system host-name edge-1'],
      identifierMappings: { version: 1, entries: [], artifact: 'SECRET-MAPPING-FIELD' },
    }));
    expect(invalid.valid).toBe(false);
    expect(invalid.error).toMatch(/identifier mapping/i);
    expect(invalid.error).not.toContain('SECRET-MAPPING-FIELD');
  });

  it('rejects malformed legacy output that claims a valid mapping', () => {
    const result = validateProjectFile(project(2, {
      commands: [], identifierMappings: IDENTIFIER_MAPPINGS,
    }));
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/conversion output/i);
  });

  it('preserves null output without clearing unrelated conversion state', () => {
    const result = validateProjectFile(project(2, null, 'xml', {
      convertWarnings: [{ type: 'retained' }],
      conversionSummary: { policies_converted: 1 },
    }));
    expect(result.valid).toBe(true);
    expect(result.project.fpic_version).toBe(5);
    expect(result.project.state.srxOutput).toBeNull();
    expect(result.project.state.outputFormat).toBe('xml');
    expect(result.project.state.convertWarnings).toEqual([{ type: 'retained' }]);
    expect(result.project.state.conversionSummary).toEqual({ policies_converted: 1 });
    expect(result.warnings).toEqual([]);
  });
});

describe('section acceptance persistence', () => {
  it('saves sectionAcceptance and defaults it for older projects', () => {
    const saved = buildProjectCore({ sectionAcceptance: { rules: true } }, 'p', { mode: 'unsanitized' });
    expect(saved.state.sectionAcceptance).toEqual({ rules: true });
    const legacy = { fpic_version: 5, state: { configText: 'x' } };
    expect(validateProjectFile(legacy).project.state.sectionAcceptance).toEqual({});
  });
});
