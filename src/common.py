"""Shared schema + serialization.

Every example is one JSON line:
  id, text, label (0 benign / 1 malicious), surface, category, family, technique, source, split

`text` is what the detector sees. Serialization is identical for train / red-team
so the model can't key on formatting:

  [CONTEXT] <optional earlier turns joined by ' || '>
  [TOOL_CALL] <tool>: <arguments>          (surface = tool_call / multi_step)
  [TOOL_OUTPUT] <tool>: <content>          (surface = tool_output)
"""
import json, unicodedata, re, base64, binascii

ZW = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)

def read_jsonl(p):
    with open(p) as f:
        return [json.loads(l) for l in f if l.strip()]

def write_jsonl(p, rows):
    with open(p, "w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def ser_call(tool, args, context=None):
    s = f"[TOOL_CALL] {tool}: {args}"
    if context:
        s = "[CONTEXT] " + " || ".join(context) + "\n" + s
    return s

def ser_out(tool, content):
    return f"[TOOL_OUTPUT] {tool}: {content}"

_B64 = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}")

def normalize(text: str) -> str:
    """Optional input normalization (ablation in eval): NFKC, strip zero-width chars,
    and append decoded form of obvious base64 / \\x-hex blobs so the classifier sees both."""
    t = unicodedata.normalize("NFKC", text).translate(ZW)
    extra = []
    for m in _B64.findall(t):
        try:
            d = base64.b64decode(m + "=" * (-len(m) % 4), validate=False).decode("utf-8")
            if d.isprintable() and len(d) >= 6:
                extra.append(d)
        except (binascii.Error, UnicodeDecodeError):
            pass
    for m in _HEX.findall(t):
        try:
            d = bytes.fromhex(m.replace("\\x", "")).decode("utf-8")
            if d.isprintable():
                extra.append(d)
        except (ValueError, UnicodeDecodeError):
            pass
    if extra:
        t += " [DECODED] " + " | ".join(extra)
    return t
