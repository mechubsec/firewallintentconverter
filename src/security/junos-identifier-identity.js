/** Encode internal identifier components without delimiter ambiguity. */
export function encodeJunosIdentifierTuple(...parts) {
  if (parts.some(part => typeof part !== 'string')) {
    throw new TypeError('Junos identifier tuple parts must be strings');
  }
  return JSON.stringify(parts);
}

/** Zone pair key; a rule-set scoped `from interface` appends that interface so it stays distinct. */
export function encodeJunosZonePair(fromZone, toZone, scopeInterface = null) {
  return scopeInterface === null
    ? encodeJunosIdentifierTuple(fromZone, toZone)
    : encodeJunosIdentifierTuple(fromZone, toZone, scopeInterface);
}
