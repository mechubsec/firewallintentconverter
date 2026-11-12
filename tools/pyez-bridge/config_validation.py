"""Fail-closed validation for converter-generated Junos configuration loads."""

import re

from lxml import etree


SUPPORTED_TOP_LEVEL = frozenset(
    {
        "system",
        "interfaces",
        "chassis",
        "security",
        "applications",
        "services",
        "routing-options",
        "routing-instances",
        "protocols",
        "policy-options",
        "class-of-service",
        "switch-options",
        "bridge-domains",
        "vlans",
        "forwarding-options",
        "firewall",
        "access",
        "snmp",
        "event-options",
        "schedulers",
        "logical-systems",
        "tenants",
    }
)
CONTEXT_WRAPPERS = frozenset({"logical-systems", "tenants"})
FORBIDDEN_PATHS = (
    ("system", "root-authentication"),
    ("system", "services", "telnet"),
    ("system", "services", "rlogin"),
    ("system", "services", "finger"),
    ("system", "scripts"),
    ("system", "extensions"),
    ("system", "extension-service"),
    ("event-options", "event-script"),
    ("event-options", "policy"),
)
FORBIDDEN_SET_CONTROL = re.compile(
    r"[\x00-\x09\x0b-\x1f\x7f-\x9f\u2028\u2029]"
)
FORBIDDEN_XML_DECLARATION = re.compile(
    r"<!DOCTYPE|<!ENTITY|<!\[CDATA\[|<\?(?!xml(?:\s|\?>))", re.I
)


class ConfigurationValidationError(ValueError):
    """A safe validation failure that never stores rejected configuration."""

    def __init__(self, reason, *, line=None, path=None):
        super().__init__(reason)
        self.reason = reason
        self.line = line
        self.path = path


def _starts_with_path(tokens, path):
    return len(tokens) >= len(path) and all(
        tokens[index] == part for index, part in enumerate(path)
    )


def _path_ends_with(path, suffix):
    return len(path) >= len(suffix) and tuple(path[-len(suffix) :]) == suffix


def _tokenize_set_line(line, line_number):
    tokens = []
    token = []
    quoted = False
    escaped = False
    index = 0

    while index < len(line):
        char = line[index]
        if escaped:
            token.append(char)
            escaped = False
        elif quoted and char == "\\":
            token.append(char)
            escaped = True
        elif char == '"':
            quoted = not quoted
            token.append(char)
        elif not quoted and char.isspace():
            if token:
                tokens.append("".join(token))
                token = []
        elif not quoted and char in ";`#{}\\":
            raise ConfigurationValidationError(
                "Command delimiters are not allowed.", line=line_number
            )
        elif not quoted and char == "$" and line[index + 1 : index + 2] == "(":
            raise ConfigurationValidationError(
                "Command substitution syntax is not allowed.", line=line_number
            )
        else:
            token.append(char)
        index += 1

    if quoted or escaped:
        raise ConfigurationValidationError(
            "Quoted value is incomplete.", line=line_number
        )
    if token:
        tokens.append("".join(token))
    return tokens


def validate_set_config(config_text):
    """Validate and normalize set-format configuration."""
    if FORBIDDEN_SET_CONTROL.search(config_text):
        raise ConfigurationValidationError(
            "Control and non-LF line-separator characters are not allowed."
        )

    accepted = []
    for line_number, raw_line in enumerate(config_text.split("\n"), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # The CLI reads "root-authentication" as root-authentication, so the
        # hierarchy checks compare tokens with quoting and escapes removed.
        tokens = [
            re.sub(r'["\\]', "", token)
            for token in _tokenize_set_line(line, line_number)
        ]
        if len(tokens) < 2 or tokens[0] not in {"set", "deactivate"}:
            raise ConfigurationValidationError(
                "Unsupported command verb.", line=line_number
            )
        if tokens[1] not in SUPPORTED_TOP_LEVEL:
            raise ConfigurationValidationError(
                "Unsupported top-level hierarchy.", line=line_number
            )

        hierarchy = tokens[1:]
        if hierarchy[0] in CONTEXT_WRAPPERS:
            hierarchy = hierarchy[2:] if len(hierarchy) >= 3 else []
        if not hierarchy or hierarchy[0] not in SUPPORTED_TOP_LEVEL:
            raise ConfigurationValidationError(
                "Context wrapper lacks a supported hierarchy.", line=line_number
            )
        if any(_starts_with_path(hierarchy, path) for path in FORBIDDEN_PATHS):
            raise ConfigurationValidationError(
                "Forbidden configuration hierarchy.", line=line_number
            )
        accepted.append(line)

    if not accepted:
        raise ConfigurationValidationError(
            "Configuration is empty after filtering."
        )
    return "\n".join(accepted)


def _element_name(element):
    if not isinstance(element.tag, str):
        return None
    if element.tag.startswith("{") or ":" in element.tag:
        raise ConfigurationValidationError(
            "XML namespaces are not supported."
        )
    return element.tag


def _inspect_xml(element, path=()):
    for child in element:
        name = _element_name(child)
        if name is None:
            continue
        child_path = (*path, name)
        if any(_path_ends_with(child_path, denied) for denied in FORBIDDEN_PATHS):
            raise ConfigurationValidationError(
                "Forbidden configuration hierarchy.",
                path="/" + "/".join(child_path),
            )
        _inspect_xml(child, child_path)


def validate_xml_config(config_text):
    """Parse XML without external resources and enforce converter hierarchies."""
    if FORBIDDEN_XML_DECLARATION.search(config_text):
        raise ConfigurationValidationError(
            "DTD, entities, CDATA, and processing instructions are not allowed."
        )

    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        huge_tree=False,
        remove_comments=False,
        strip_cdata=False,
    )
    try:
        root = etree.fromstring(config_text.encode("utf-8"), parser)
    except (etree.XMLSyntaxError, ValueError, UnicodeError):
        raise ConfigurationValidationError("XML is not well formed.") from None

    root_name = _element_name(root)
    if root_name != "configuration":
        raise ConfigurationValidationError(
            "The root element must be configuration.", path="/"
        )
    if root.getprevious() is not None or root.getnext() is not None:
        raise ConfigurationValidationError(
            "Content outside the configuration root is not allowed.", path="/"
        )
    if root.getroottree().docinfo.doctype:
        raise ConfigurationValidationError("DTD declarations are not allowed.")

    for child in root:
        name = _element_name(child)
        if name is not None and name not in SUPPORTED_TOP_LEVEL:
            raise ConfigurationValidationError(
                "Unsupported top-level hierarchy.",
                path=f"/configuration/{name}",
            )
    _inspect_xml(root)
    return config_text


def validate_config_payload(config_text, fmt):
    """Validate one browser bridge load payload for the supported subset."""
    if not isinstance(config_text, str):
        raise ConfigurationValidationError("Configuration must be text.")
    if fmt == "set":
        return validate_set_config(config_text)
    if fmt == "xml":
        return validate_xml_config(config_text)
    raise ConfigurationValidationError(
        "Only set and XML configuration loads are supported."
    )
