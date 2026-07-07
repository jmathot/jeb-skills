"""
Phase 2b: Web Application Code Extraction.

Consumes the deduplicated web-code corpus produced by ingest.py
(`*_webcode.json`) and turns each unique HTML/JS/CSS artifact into
tag/structure-aware chunks with security-hunting metadata.

Output chunks share the same shape as chunker.py ({"page_content", "metadata"})
so vector_store.py can embed them into a separate `web_code` collection.

Design decisions (per engagement plan):
  * HTML is split at tag boundaries: each <script>, <form>, inline event
    handler, and the residual DOM skeleton become their own chunks.
  * External JavaScript is classified first-party vs vendor/minified. First-party
    code is chunked by function/size and embedded; vendor/minified bundles are
    kept as a single store-only chunk (embed=false) so they remain retrievable
    by id without polluting semantic search.
  * CSS is kept store-only (low value for semantic search).
"""
import json
import argparse
import os
import re
import hashlib
from urllib.parse import urlparse

from bs4 import BeautifulSoup

# ---- Chunk sizing -----------------------------------------------------------
MAX_CHUNK_CHARS = 4000          # target size for embeddable code chunks
VENDOR_MIN_BYTES = 1500         # below this, even minified code is cheap to embed

# ---- Vendor / minified detection -------------------------------------------
VENDOR_PATH_SIGNALS = (
    'node_modules', 'vendor', 'vendors', 'bundle', 'polyfill', 'runtime',
    'jquery', 'react', 'react-dom', 'angular', 'vue', 'bootstrap', 'lodash',
    'underscore', 'moment', 'axios', 'd3', 'three', 'chart', 'modernizr',
    'require', 'webpack', 'gtm', 'gtag', 'analytics', 'recaptcha',
)

# ---- Hunting patterns -------------------------------------------------------
SECRET_PATTERNS = [
    re.compile(r'AKIA[0-9A-Z]{16}'),                         # AWS access key id
    re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                   # Google API key
    re.compile(r'ghp_[0-9A-Za-z]{36}'),                      # GitHub token
    re.compile(r'sk_(?:live|test)_[0-9A-Za-z]{10,}'),        # Stripe secret
    re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}'),            # Slack token
    re.compile(r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),  # JWT
    re.compile(r'(?i)(?:api[_-]?key|secret|passwd|password|token|access[_-]?key)'
               r'["\']?\s*[:=]\s*["\'][^"\']{8,}["\']'),
    re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |PRIVATE)'),  # private key blob
]

DOM_SINKS = (
    'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write',
    'document.writeln', 'eval(', 'setTimeout(', 'setInterval(',
    'Function(', 'dangerouslySetInnerHTML', 'location.href',
    'location.assign', 'location.replace', '.src', 'srcdoc',
    'postMessage', 'localStorage', 'sessionStorage', 'document.cookie',
)

ENDPOINT_RE = re.compile(
    r'''(?:fetch|axios(?:\.\w+)?|\.open|XMLHttpRequest|\.ajax|url\s*[:=])\s*'''
    r'''\(?\s*["'`]([^"'`]+)["'`]'''
)
URL_PATH_RE = re.compile(r'["\'`](/[A-Za-z0-9_\-./]{2,}(?:\?[^"\'`]*)?)["\'`]')


def _hash(text: str) -> str:
    return hashlib.md5(text.encode('utf-8')).hexdigest()


def find_secrets(text: str) -> bool:
    return any(p.search(text) for p in SECRET_PATTERNS)


def find_dom_sinks(text: str):
    return sorted({s.rstrip('(') for s in DOM_SINKS if s in text})


def find_endpoints(text: str, limit: int = 25):
    found = []
    for m in ENDPOINT_RE.finditer(text):
        found.append(m.group(1))
    for m in URL_PATH_RE.finditer(text):
        found.append(m.group(1))
    # de-dup preserving order, cap the list to keep metadata small
    seen = set()
    out = []
    for e in found:
        if e not in seen:
            seen.add(e)
            out.append(e)
        if len(out) >= limit:
            break
    return out


def is_vendor_js(body: str, source_urls) -> bool:
    """Heuristic: known vendor path, or clearly minified and large."""
    for u in source_urls:
        low = u.lower()
        if '.min.js' in low or any(sig in low for sig in VENDOR_PATH_SIGNALS):
            return True
    # Minification heuristic: very long average line length on a large file.
    if len(body) > VENDOR_MIN_BYTES:
        lines = body.split('\n')
        if lines:
            avg_line = len(body) / max(1, len(lines))
            if avg_line > 250:
                return True
    return False


def split_js(body: str):
    """Chunk JS by function/logical boundaries, falling back to size splits."""
    if len(body) <= MAX_CHUNK_CHARS:
        return [body]

    # Split before common top-level declarations, keeping the delimiter.
    boundary = re.compile(
        r'(?=(?:^|\n)\s*(?:export\s+)?(?:async\s+)?function\s|'
        r'(?:^|\n)\s*(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?\(|'
        r'(?:^|\n)\s*class\s+\w+|'
        r'(?:^|\n)\s*[\w$]+\s*:\s*function)'
    )
    pieces = boundary.split(body)
    chunks = []
    buf = ''
    for piece in pieces:
        if not piece:
            continue
        if len(buf) + len(piece) > MAX_CHUNK_CHARS and buf:
            chunks.append(buf)
            buf = piece
        else:
            buf += piece
    if buf:
        chunks.append(buf)

    # Hard-split any oversized piece that had no usable boundaries.
    final = []
    for c in chunks:
        if len(c) <= MAX_CHUNK_CHARS:
            final.append(c)
        else:
            for i in range(0, len(c), MAX_CHUNK_CHARS):
                final.append(c[i:i + MAX_CHUNK_CHARS])
    return final or [body]


def make_chunk(text, code_type, artifact, chunk_index, total_chunks, embed):
    source_urls = artifact.get('source_urls', [])
    source_url = source_urls[0] if source_urls else ''
    host = artifact.get('host', '') or (urlparse(source_url).hostname or '')
    endpoints = find_endpoints(text)
    metadata = {
        "content_kind": "web_code",
        "code_type": code_type,
        "host": host,
        "source_url": source_url,
        "source_urls": ",".join(source_urls[:20]),
        "url_count": len(source_urls),
        "artifact_hash": artifact.get('hash', _hash(text)),
        "chunk_index": chunk_index,
        "total_chunks": total_chunks,
        "embed": bool(embed),
        "has_secrets": find_secrets(text),
        "dom_sinks": ",".join(find_dom_sinks(text)),
        "endpoints": ",".join(endpoints),
        "endpoint_count": len(endpoints),
        "chunk_len": len(text),
    }
    header = f"// web_code {code_type} | {source_url} [{chunk_index + 1}/{total_chunks}]\n"
    return {"page_content": header + text, "metadata": metadata}


def extract_html(artifact):
    """Split HTML into script / form / event-handler / DOM-skeleton chunks."""
    body = artifact.get('body', '')
    soup = BeautifulSoup(body, 'html.parser')
    raw_chunks = []  # (text, code_type)

    # Inline and external scripts.
    for script in soup.find_all('script'):
        src = script.get('src')
        if src:
            raw_chunks.append((f"<script src=\"{src}\"></script>", "script_ref"))
        else:
            content = script.string or script.get_text() or ''
            if content.strip():
                raw_chunks.append((content, "inline_js"))

    # Forms: action/method/inputs are prime testing targets.
    for form in soup.find_all('form'):
        action = form.get('action', '')
        method = form.get('method', 'GET')
        fields = []
        for inp in form.find_all(['input', 'select', 'textarea', 'button']):
            name = inp.get('name') or inp.get('id') or ''
            itype = inp.get('type', inp.name)
            fields.append(f"{name}:{itype}")
        summary = f"<form action=\"{action}\" method=\"{method}\">\n" + "\n".join(fields)
        raw_chunks.append((summary, "form"))

    # Inline event handlers (onclick, onload, ...): DOM XSS / logic surface.
    handlers = []
    for el in soup.find_all(True):
        for attr, val in list(el.attrs.items()):
            if attr.lower().startswith('on') and val:
                handlers.append(f"<{el.name} {attr}=\"{val}\">")
    if handlers:
        raw_chunks.append(("\n".join(handlers), "event_handler"))

    # Residual DOM skeleton (scripts/styles removed, whitespace collapsed).
    skeleton_soup = BeautifulSoup(body, 'html.parser')
    for tag in skeleton_soup(['script', 'style', 'svg', 'noscript']):
        tag.decompose()
    skeleton = re.sub(r'\n\s*\n+', '\n', str(skeleton_soup))
    if skeleton.strip():
        raw_chunks.append((skeleton, "html"))

    return raw_chunks


def process_artifact(artifact):
    code_type = artifact.get('code_type', '')
    body = artifact.get('body', '')
    source_urls = artifact.get('source_urls', [])
    out = []

    if code_type == 'html':
        raw = extract_html(artifact)
        # Further split any oversized inline_js / html blocks.
        expanded = []
        for text, ct in raw:
            if ct in ('inline_js', 'html') and len(text) > MAX_CHUNK_CHARS:
                for piece in split_js(text) if ct == 'inline_js' else \
                        [text[i:i + MAX_CHUNK_CHARS] for i in range(0, len(text), MAX_CHUNK_CHARS)]:
                    expanded.append((piece, ct))
            else:
                expanded.append((text, ct))
        total = len(expanded)
        for i, (text, ct) in enumerate(expanded):
            out.append(make_chunk(text, ct, artifact, i, total, embed=True))

    elif code_type == 'javascript':
        vendor = is_vendor_js(body, source_urls)
        if vendor:
            # Store-only: one chunk, not embedded.
            out.append(make_chunk(body, "vendor_js", artifact, 0, 1, embed=False))
        else:
            pieces = split_js(body)
            total = len(pieces)
            for i, piece in enumerate(pieces):
                out.append(make_chunk(piece, "external_js", artifact, i, total, embed=True))

    elif code_type == 'css':
        # Store-only, low priority for semantic search.
        out.append(make_chunk(body, "css", artifact, 0, 1, embed=False))

    return out


def main():
    parser = argparse.ArgumentParser(description="Phase 2b: Web application code extraction")
    parser.add_argument("input_file", help="Path to the *_webcode.json corpus from ingest.py")
    parser.add_argument("-o", "--output", help="Output JSON file", default="code_chunks.json")
    args = parser.parse_args()

    try:
        with open(args.input_file, 'r') as f:
            artifacts = json.load(f)
    except FileNotFoundError:
        print(f"Error: Could not find {args.input_file}")
        return

    chunks = []
    for artifact in artifacts:
        chunks.extend(process_artifact(artifact))

    with open(args.output, 'w') as f:
        json.dump(chunks, f, indent=2)

    embedded = sum(1 for c in chunks if c['metadata'].get('embed'))
    print(f"Extracted {len(chunks)} code chunks from {len(artifacts)} artifacts "
          f"({embedded} to embed, {len(chunks) - embedded} store-only). Saved to {args.output}")


if __name__ == '__main__':
    main()
