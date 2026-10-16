const PLACEHOLDER_RE = /^SANITIZED_(?:HASH|KEY|COMMUNITY|CERT)_\d+$/;
const KEY_RE = /^(?:password|passwd|passwordhash|phash|encryptedpassword|secret|sharedsecret|secondarysecret|psk|presharedkey|psksecret|authkey|authenticationkey|authenticationpassword|privacykey|privacypassword|apikey|snmpcommunity|radiussecret|radiuskey|tacacssecret|tacacskey|tacplussecret|tacpluskey|privatekey|certificatekey)$/;
const INCOMPLETE_SCOPE_FINDING = Object.freeze({
  category: 'scope',
  ruleId: 'fortigate-incomplete-sensitive-block',
});

export class SecretScopeError extends Error {
  constructor() {
    super('Sensitive FortiGate configuration block is incomplete.');
    this.name = 'SecretScopeError';
    this.code = 'incomplete_sensitive_scope';
  }
}

function normalizedKey(key) {
  return String(key).replace(/[^a-z0-9]/gi, '').toLowerCase();
}

function syntax(ruleId, category, placeholderKind, regex, valueGroups, render) {
  return Object.freeze({ ruleId, category, placeholderKind, regex, valueGroups, render });
}

function blockSyntax(
  ruleId,
  category,
  placeholderKind,
  blockHeader,
  entryRegex,
  valueGroups,
  render,
) {
  return Object.freeze({
    ruleId,
    category,
    placeholderKind,
    blockHeader,
    entryRegex,
    valueGroups,
    render,
  });
}

const quotedOrBare = (groups, placeholder) => groups[1] + placeholder;
const quoted = (groups, placeholder) => groups[1] + '"' + placeholder + '"';
const fortigateBlockEntry = (groups, placeholder) => (
  groups[3] !== undefined
    ? groups[1] + '"' + placeholder + '"'
    : groups[1] + placeholder
);

function nextLineEnd(text, start) {
  const newline = text.indexOf('\n', start);
  const carriage = text.indexOf('\r', start);
  if (newline < 0 && carriage < 0) return text.length;
  if (carriage >= 0 && (newline < 0 || carriage < newline)) {
    return carriage + (text[carriage + 1] === '\n' ? 2 : 1);
  }
  return newline + 1;
}

function lineWithoutEnding(text, start, end) {
  let contentEnd = end;
  if (contentEnd > start && text[contentEnd - 1] === '\n') contentEnd -= 1;
  if (contentEnd > start && text[contentEnd - 1] === '\r') contentEnd -= 1;
  return text.slice(start, contentEnd);
}

function matchesLine(regex, line) {
  regex.lastIndex = 0;
  return regex.test(line);
}

function fortigateBlockRegions(text, targetHeader) {
  const regions = [];
  let blockStart = -1;
  let depth = 0;
  let lineStart = 0;
  while (lineStart < text.length) {
    const lineEnd = nextLineEnd(text, lineStart);
    const line = lineWithoutEnding(text, lineStart, lineEnd);
    if (blockStart < 0) {
      if (matchesLine(targetHeader, line)) {
        blockStart = lineStart;
        depth = 1;
      }
    } else if (/^[ \t]*config(?:[ \t]+|$)/i.test(line)) {
      depth += 1;
    } else if (/^[ \t]*end[ \t]*$/i.test(line)) {
      depth -= 1;
      if (depth === 0) {
        regions.push(Object.freeze({ start: blockStart, end: lineEnd, incomplete: false }));
        blockStart = -1;
      }
    }
    lineStart = lineEnd;
  }
  if (blockStart >= 0) {
    regions.push(Object.freeze({
      start: blockStart,
      end: text.length,
      incomplete: true,
    }));
  }
  return regions;
}

const SECRET_SYNTAXES = Object.freeze([
  syntax('xml-nested-key', 'key', 'KEY', /(<(?:pre-shared-key|api-key|auth-key|secret|key)>\s*<key>)([^<]+)(<\/key>)/gi, 2,
    (groups, placeholder) => groups[1] + placeholder + groups[3]),
  syntax('xml-direct-key', 'key', 'KEY', /(<(?:pre-shared-key|api-key|auth-key|secret)>)(?!\s*<key>)([^<]+)(<\/[^>]+>)/gi, 2,
    (groups, placeholder) => groups[1] + placeholder + groups[3]),
  syntax('xml-hash', 'hash', 'HASH', /(<(?:phash|password-hash|encrypted-secret)>)([^<]+)(<\/[^>]+>)/gi, 2,
    (groups, placeholder) => groups[1] + placeholder + groups[3]),
  syntax('xml-private-key', 'certificate', 'CERT', /(<(?:private-key|certificate-key|ssl-key|secret-key)>)([^<]+)(<\/[^>]+>)/gi, 2,
    (groups, placeholder) => groups[1] + placeholder + groups[3]),
  syntax('xml-snmp-community', 'community', 'COMMUNITY', /(<community>)([^<]+)(<\/community>)/gi, 2,
    (groups, placeholder) => groups[1] + placeholder + groups[3]),
  syntax('attribute-hash', 'hash', 'HASH', /(^|\n)(\s*(?:password|secret|pre-shared-key|auth-key)\s+")((?:\$)[^"]+)(")/gi, 3,
    (groups, placeholder) => groups[1] + groups[2] + placeholder + groups[4]),

  syntax('fortigate-enc-password', 'hash', 'HASH', /(set\s+(?:password|passwd)\s+)(ENC\s+(?:"[^"]+"|\S+))/gi, 2, quotedOrBare),
  syntax('fortigate-quoted-password', 'hash', 'HASH', /(set\s+(?:password|passwd)\s+)"([^"]+)"/gi, 2, quoted),
  syntax('fortigate-unquoted-password', 'hash', 'HASH', /(set\s+(?:password|passwd)\s+)(?!ENC\s|")(\S+)/gi, 2, quotedOrBare),
  syntax('fortigate-enc-secret', 'key', 'KEY', /(set\s+(?:secret|secondary-secret|psksecret|tacacs-secret|auth-password|privacy-password)\s+)(ENC\s+(?:"[^"]+"|\S+))/gi, 2, quotedOrBare),
  syntax('fortigate-quoted-secret', 'key', 'KEY', /(set\s+(?:secret|secondary-secret|psksecret|tacacs-secret|auth-password|privacy-password)\s+)"([^"]+)"/gi, 2, quoted),
  syntax('fortigate-unquoted-secret', 'key', 'KEY', /(set\s+(?:secret|secondary-secret|psksecret|tacacs-secret|auth-password|privacy-password)\s+)(?!ENC\s|")(\S+)/gi, 2, quotedOrBare),

  blockSyntax(
    'fortigate-tacacs-block-key',
    'key',
    'KEY',
    /^[ \t]*config[ \t]+user[ \t]+tacacs\+[ \t]*$/i,
    /(^[ \t]*set[ \t]+key[ \t]+)(?:(ENC[ \t]+(?:"[^"\r\n]+"|\S+))|"([^"\r\n]+)"|(\S+))[ \t]*$/gim,
    [2, 3, 4],
    fortigateBlockEntry,
  ),
  blockSyntax(
    'fortigate-snmp-block-name',
    'community',
    'COMMUNITY',
    /^[ \t]*config[ \t]+system[ \t]+snmp[ \t]+community[ \t]*$/i,
    /(^[ \t]*set[ \t]+name[ \t]+)(?:(ENC[ \t]+(?:"[^"\r\n]+"|\S+))|"([^"\r\n]+)"|(\S+))[ \t]*$/gim,
    [2, 3, 4],
    fortigateBlockEntry,
  ),

  syntax('fortigate-enc-community', 'community', 'COMMUNITY', /(set\s+community\s+)(ENC\s+(?:"[^"]+"|\S+))/gi, 2, quotedOrBare),
  syntax('asa-snmp-host-community', 'community', 'COMMUNITY', /(snmp-server\s+host\s+\S+\s+\S+[^\r\n]*?\scommunity\s+)(\S+)/gi, 2, quotedOrBare),
  syntax('snmp-community-cli', 'community', 'COMMUNITY', /((?:set\s+snmp\s+community|snmp-server\s+community|set\s+community)\s+)(?!ENC\s)(?:"([^"]+)"|(\S+))/gi, [2, 3], quotedOrBare),
  syntax('snmp-community-hierarchical', 'community', 'COMMUNITY', /(\bcommunity\s+)(?:"([^"]+)"|([^\s{;]+))(\s*\{)/gi, [2, 3],
    (groups, placeholder) => groups[1] + placeholder + groups[4]),
  syntax('aaa-secret-cli', 'key', 'KEY', /((?:radius-server|tacacs-server|tacplus-server|set\s+system\s+(?:radius-server|tacplus-server))\s+(?:host\s+)?\S+\s+(?:secret|key)\s+)(?:"([^"]+)"|([^\s;]+))/gi, [2, 3], quoted),
  syntax('asa-aaa-server-key', 'key', 'KEY', /((?:^|\n)\s*aaa-server\s+\S+\s+\([^\)\r\n]+\)\s+host\s+\S+\s*\r?\n\s*(?:key|secret)\s+)(?:"([^"]+)"|(\S+))/gim, [2, 3], quoted),
  syntax('aaa-secret-hierarchical', 'key', 'KEY', /((?:radius-server|tacacs-server|tacplus-server)\s+\S+\s*\{\s*(?:[^{};\s][^{};]*;\s*)*(?:secret|key)\s+)(?:"([^"]+)"|([^\s;}]+))/gi, [2, 3], quoted),

  syntax('cli-pre-shared-key', 'key', 'KEY', /((?:(?:ikev[12]\s+(?:(?:local|remote)-authentication\s+)?)?pre-shared-key\s+)(?:(?:ascii-text|hexadecimal)\s+)?)(?!\{)(?:"([^"]+)"|([^\s;]+))/gi, [2, 3], quoted),
  syntax('hierarchical-pre-shared-key', 'key', 'KEY', /(pre-shared-key\s*\{\s*(?:ascii-text|hexadecimal)\s+)(?:"([^"]+)"|([^\s;}]+))/gi, [2, 3], quoted),
  syntax('asa-isakmp-key', 'key', 'KEY', /(crypto\s+isakmp\s+key\s+)(\S+)/gi, 2, quotedOrBare),
  syntax('encrypted-password', 'hash', 'HASH', /((?:encrypted-password|enable\s+secret)\s+)(?:"([^"]+)"|([^\s;]+))/gi, [2, 3], quoted),
  syntax('enable-password', 'hash', 'HASH', /((?:enable\s+)?password\s+)(\S+)(\s+encrypted\b)/gi, 2,
    (groups, placeholder) => groups[1] + placeholder + groups[3]),
  syntax('username-password', 'hash', 'HASH', /(username\s+\S+\s+(?:password|secret)\s+)(?:"([^"]+)"|(\S+))/gi, [2, 3], quotedOrBare),
  syntax('auth-privacy-password', 'key', 'KEY', /((?:authentication-password|privacy-password|authentication-key|privacy-key)\s+)(?:"([^"]+)"|([^\s;]+))/gi, [2, 3], quoted),
  syntax('cli-private-key', 'certificate', 'CERT', /((?:private-key|certificate-key|ssl-key|secret-key)\s+)(?:"([^"]+)"|([^\s;]+))/gi, [2, 3], quoted),

  syntax('json-secret', 'key', 'KEY', /("(?:shared-secret|pre-shared-key|psksecret|radius-secret|radius-key|tacacs-secret|tacacs-key|tacplus-secret|tacplus-key)"\s*:\s*")([^"]+)(")/gi, 2,
    (groups, placeholder) => groups[1] + placeholder + groups[3]),
  syntax('json-password-hash', 'hash', 'HASH', /("(?:password|password-hash|phash|encrypted-password)"\s*:\s*")([^"]+)(")/gi, 2,
    (groups, placeholder) => groups[1] + placeholder + groups[3]),
  syntax('json-snmp-community', 'community', 'COMMUNITY', /("snmp-community"\s*:\s*")([^"]+)(")/gi, 2,
    (groups, placeholder) => groups[1] + placeholder + groups[3]),
  syntax('json-private-key', 'certificate', 'CERT', /("(?:private-key|certificate-key|ssl-key|secret-key|certificate-secret)"\s*:\s*")([^"]+)(")/gi, 2,
    (groups, placeholder) => groups[1] + placeholder + groups[3]),
  syntax('text-aaa-secret', 'key', 'KEY', /((?:radius|tacacs|tacplus)[ -](?:secret|key)\s*:\s*)(\S+)/gi, 2, quotedOrBare),
  syntax('text-private-key', 'certificate', 'CERT', /((?:private[ -]key|certificate[ -](?:key|secret)|ssl[ -]key)\s*:\s*)(\S+)/gi, 2, quotedOrBare),

  syntax('sonicwall-secret', 'key', 'KEY', /((?:Shared Secret|Pre-Shared Key)\s*:\s*)(\S+)/gi, 2, quotedOrBare),
  syntax('sonicwall-password-hash', 'hash', 'HASH', /(Password Hash\s*:\s*)(\S+)/gi, 2, quotedOrBare),
  syntax('sonicwall-password', 'hash', 'HASH', /(Password\s*:\s*)(\S+)/gi, 2, quotedOrBare),
  syntax('sonicwall-snmp-community', 'community', 'COMMUNITY', /(SNMP Community\s*:\s*)(\S+)/gi, 2, quotedOrBare),

  syntax('pem-private-key', 'certificate', 'CERT', /-----BEGIN\s+(?:(?:RSA|EC|DSA|ENCRYPTED|OPENSSH)\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:(?:RSA|EC|DSA|ENCRYPTED|OPENSSH)\s+)?PRIVATE\s+KEY-----/g, 0,
    (_groups, placeholder) => placeholder),
]);

function cloneRegex(regex) {
  return new RegExp(regex.source, regex.flags);
}

function secretValue(spec, groups) {
  const indexes = Array.isArray(spec.valueGroups) ? spec.valueGroups : [spec.valueGroups];
  for (const index of indexes) {
    if (groups[index] !== undefined) return groups[index];
  }
  return undefined;
}

export function isSanitizedSecretValue(value) {
  return typeof value === 'string' && PLACEHOLDER_RE.test(value);
}

export function isSecretBearingKey(key) {
  return KEY_RE.test(normalizedKey(key));
}

export function findSecretsInText(text) {
  if (typeof text !== 'string') return [];
  const findings = [];
  for (const spec of SECRET_SYNTAXES) {
    const regions = spec.blockHeader
      ? fortigateBlockRegions(text, spec.blockHeader)
      : [{ start: 0, end: text.length, incomplete: false }];
    const entryRegex = spec.blockHeader ? spec.entryRegex : spec.regex;
    for (const region of regions) {
      const regionText = text.slice(region.start, region.end);
      for (const match of regionText.matchAll(cloneRegex(entryRegex))) {
        const original = secretValue(spec, match);
        if (!original || isSanitizedSecretValue(original.trim())) continue;
        findings.push({ category: spec.category, ruleId: spec.ruleId });
      }
      if (region.incomplete) findings.push(INCOMPLETE_SCOPE_FINDING);
    }
  }
  return findings;
}

export function redactConfigSecrets(text) {
  if (typeof text !== 'string') throw new TypeError('configuration text must be a string');
  const counters = { HASH: 0, KEY: 0, COMMUNITY: 0, CERT: 0 };
  for (const match of text.matchAll(/SANITIZED_(HASH|KEY|COMMUNITY|CERT)_(\d+)/g)) {
    counters[match[1]] = Math.max(counters[match[1]], Number(match[2]) + 1);
  }
  const counts = { hash: 0, key: 0, community: 0, cert: 0 };
  const replacements = [];
  let output = text;
  for (const spec of SECRET_SYNTAXES) {
    const replaceEntry = (...args) => {
      const groups = args.slice(0, -2);
      const captured = secretValue(spec, groups);
      const original = captured?.trim();
      if (!original || isSanitizedSecretValue(original)) return groups[0];
      const placeholder = 'SANITIZED_' + spec.placeholderKind + '_' + counters[spec.placeholderKind]++;
      replacements.push({ type: spec.category, placeholder, original });
      counts[spec.category === 'certificate' ? 'cert' : spec.category] += 1;
      return spec.render(groups, placeholder);
    };
    if (spec.blockHeader) {
      const regions = fortigateBlockRegions(output, spec.blockHeader);
      if (regions.some(region => region.incomplete)) throw new SecretScopeError();
      const source = output;
      const segments = [];
      let cursor = 0;
      for (const { start, end } of regions) {
        segments.push(source.slice(cursor, start));
        const block = source.slice(start, end);
        segments.push(block.replace(cloneRegex(spec.entryRegex), replaceEntry));
        cursor = end;
      }
      segments.push(source.slice(cursor));
      output = segments.join('');
    } else {
      output = output.replace(cloneRegex(spec.regex), replaceEntry);
    }
  }
  return { text: output, replacements, counts };
}
