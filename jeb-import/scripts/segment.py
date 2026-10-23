"""
Page segmentation that does not depend on heading tags.

Real sites lay content out with divs, put it in script blocks or render it on the
client, so headings cannot decide where to split. Layers, in order, over the one
BeautifulSoup tree `distill._html_view` already parses:

1. script-embedded data (`pre_clean`): JSON-LD, `__NEXT_DATA__`, `window.__X__ = {}`
   payloads become data-object signatures; inline JS is kept for `jsfacts`.
2. boilerplate removal (`select`): every chunk carries a content hash; chunks whose
   hash is template on the host (see `normalize.pass_c_boilerplate`) are dropped,
   whether or not they sit in nav/footer/aside tags.
3. repeated-structure collapse (`_pieces`): runs of sibling subtrees with one shape
   become a single `listing` chunk.
4. DOM budget-fit split (`_pieces`): a subtree that fits SECTION_CAP is one chunk;
   an oversized one is recursed into and small neighbours merged up to the cap.
5. text-window fallback (`window_split`): a flat leaf over the cap is cut into
   overlapping windows at sentence boundaries.

Everything is deterministic and uses no embedding calls.
"""
import hashlib
import json
import re
from urllib.parse import urlparse

from bs4 import NavigableString, Tag

SECTION_CAP = 2500          # chars of one chunk
SECTION_MIN_CHARS = 300     # a chunk is never a lone button
PAGE_EMBED_CAP = 4000       # a page whose cleaned text fits is held whole by its node
MAX_SECTIONS_PER_PAGE = 8
REPEAT_MIN = 3              # siblings of one shape before they collapse
LISTING_MIN_CHARS = 800     # a repeated run shorter than this stays inline text
LISTING_ITEM_MAX = 400      # average item text above this is content, not a list row
WINDOW_OVERLAP = 0.10
LABEL_CAP = 80
LEAD_CHARS = 600
MAX_PAYLOADS = 6
MAX_FORMS = 8
MAX_LINKS = 60
MAX_LOADS = 12
INLINE_JS_CAP = 200_000
PAYLOAD_CAP = 200_000

_HEADING_TAGS = ('h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'legend', 'caption', 'summary')
_TITLE_CLASS = re.compile(r'title|header|heading', re.I)
_ASSIGNED_STATE = re.compile(
    r'(?:window\.)?(__[A-Z0-9_]+__|[A-Za-z_$][\w$]*(?:State|Data|Store|Props|Config))\s*=\s*(?=[\[{])')
_SENTENCE_END = re.compile(r'(?<=[.!?])\s+')


def _md5(text):
    return hashlib.md5(text.encode()).hexdigest()


def chunk_hash(text):
    return _md5(text)[:12]


def _text(node):
    return ' '.join(node.get_text(' ').split()) if isinstance(node, Tag) else ' '.join(str(node).split())


# ---------------------------------------------------------------------------
# Layer 1: script-embedded data
# ---------------------------------------------------------------------------
def _decode_json_prefix(text):
    start = min((i for i in (text.find('{'), text.find('[')) if i >= 0), default=-1)
    if start < 0:
        return None
    try:
        obj, _ = json.JSONDecoder().raw_decode(text[start:])
        return obj
    except ValueError:
        return None


def pre_clean(soup):
    """Run before scripts are removed. -> {'payloads', 'inline_js', 'loads'}."""
    payloads, inline, loads = [], [], []
    for script in soup.find_all('script'):
        src = script.get('src')
        if src:
            parsed = urlparse(src.strip())
            if parsed.path and len(loads) < MAX_LOADS:
                loads.append(((parsed.scheme + '://' + parsed.netloc) if parsed.netloc else '') + parsed.path)
            continue
        text = (script.string or script.get_text() or '')[:PAYLOAD_CAP]
        if not text.strip():
            continue
        kind = (script.get('type') or '').lower()
        obj = None
        if kind in ('application/ld+json', 'application/json', 'application/vnd.api+json') \
                or script.get('id') == '__NEXT_DATA__':
            try:
                obj = json.loads(text)
            except ValueError:
                obj = None
        elif 'javascript' in kind or kind in ('', 'module'):
            match = _ASSIGNED_STATE.search(text)
            if match:
                obj = _decode_json_prefix(text[match.end():])
        if obj is not None and isinstance(obj, (dict, list)) and obj:
            if len(payloads) < MAX_PAYLOADS:
                payloads.append(json.dumps(obj, separators=(',', ':'))[:PAYLOAD_CAP])
            continue
        if kind in ('', 'module') or 'javascript' in kind:
            inline.append(text)
    return {'payloads': payloads, 'inline_js': '\n'.join(inline)[:INLINE_JS_CAP], 'loads': loads}


# ---------------------------------------------------------------------------
# Forms and links (structured, for edges)
# ---------------------------------------------------------------------------
def structured_forms(soup):
    forms = []
    for form in soup.find_all('form')[:MAX_FORMS]:
        fields = []
        for field in form.find_all(['input', 'select', 'textarea', 'button']):
            name = field.get('name') or field.get('id')
            if name and name not in fields:
                fields.append(name)
        forms.append({'method': (form.get('method') or 'GET').upper(),
                      'action': (form.get('action') or '').strip()[:200],
                      'fields': fields[:30]})
    return forms


def raw_links(soup):
    links = []
    for a in soup.find_all('a', href=True):
        href = a['href'].strip()
        parsed = urlparse(href)
        if not href or href.startswith('#') or parsed.scheme in ('javascript', 'mailto', 'tel', 'data', 'sms'):
            continue
        target = (((parsed.scheme + '://' + parsed.netloc) if parsed.netloc else '') + parsed.path) or '/'
        if target not in links:
            links.append(target)
        if len(links) >= MAX_LINKS:
            break
    return links


# ---------------------------------------------------------------------------
# Layers 3-5: chunking
# ---------------------------------------------------------------------------
def _label(node):
    """First heading-like descendant, else the node's own id / aria-label."""
    if not isinstance(node, Tag):
        return ''
    heading = node.find(_HEADING_TAGS) or node.find(attrs={'role': 'heading'})
    if heading is None:
        for strong in node.find_all(['strong', 'b'], limit=1):
            lead = _text(node)[:len(_text(strong)) + 2]
            if lead.startswith(_text(strong)):
                heading = strong
        if heading is None:
            for el in node.find_all(True, limit=40):
                hint = ' '.join(filter(None, [el.get('id', ''), ' '.join(el.get('class', []) or [])]))
                if _TITLE_CLASS.search(hint) and _text(el):
                    heading = el
                    break
    text = _text(heading) if heading is not None else ''
    if not text:
        text = node.get('aria-label') or node.get('id') or ''
    return text[:LABEL_CAP]


def _shape(tag):
    return '{}:{}>{}'.format(tag.name, '.'.join(sorted(tag.get('class', []) or [])),
                             ','.join(c.name for c in tag.children if isinstance(c, Tag)))


def window_split(text, cap=SECTION_CAP, overlap=WINDOW_OVERLAP):
    """Overlapping windows of at most `cap` chars, cut at sentence ends when possible."""
    if len(text) <= cap:
        return [text]
    windows, start = [], 0
    step_back = int(cap * overlap)
    while start < len(text):
        end = min(len(text), start + cap)
        if end < len(text):
            cut = max((m.end() for m in _SENTENCE_END.finditer(text, start, end)), default=0)
            if cut > start + cap // 2:
                end = cut
        windows.append(text[start:end].strip())
        if end >= len(text):
            break
        start = max(start + 1, end - step_back)
    return [w for w in windows if w]


def _listing(run):
    first = run[0]
    fields = []
    for leaf in first.find_all(True):
        if not any(isinstance(c, Tag) for c in leaf.children):
            label = _text(leaf)[:40]
            if label and label not in fields:
                fields.append(label)
        if len(fields) >= 8:
            break
    targets = []
    for a in first.find_all('a', href=True):
        path = urlparse(a['href']).path
        if path and path not in targets:
            targets.append(path)
        if len(targets) >= 4:
            break
    samples = [_text(item)[:200] for item in run[:3]]
    text = f"listing of {len(run)} similar items | item shape: {', '.join(fields) or '-'}"
    if targets:
        text += f" | item links: {', '.join(targets)}"
    text += ' | samples: ' + ' ; '.join(samples)
    return (_label(run[0]) or _label(run[0].parent), 'listing', text)


def _runs(kids):
    runs, current, last = [], [], None
    for kid in kids:
        shape = _shape(kid)
        if current and shape == last:
            current.append(kid)
        else:
            if current:
                runs.append(current)
            current, last = [kid], shape
    if current:
        runs.append(current)
    return runs


def _qualifying(run):
    """A run collapses only when its items are card/row sized. Long items (an FAQ,
    a set of articles) are content in their own right and are split, not sampled."""
    if len(run) < REPEAT_MIN:
        return False
    total = sum(len(_text(k)) for k in run)
    return total >= LISTING_MIN_CHARS and total / len(run) <= LISTING_ITEM_MAX


def _mark_listings(root):
    """ids of every node that is, or contains, a repeated-structure run."""
    marked = set()
    for el in [root] + root.find_all(True):
        kids = [c for c in el.children if isinstance(c, Tag) and _text(c)]
        if len(kids) >= REPEAT_MIN and any(_qualifying(run) for run in _runs(kids)):
            node = el
            while node is not None and id(node) not in marked:
                marked.add(id(node))
                if node is root:
                    break
                node = node.parent
    return marked


def _pieces(node, marked):
    text = _text(node)
    if not text:
        return []
    kids = [c for c in node.children if isinstance(c, Tag) and _text(c)]
    runs = _runs(kids)
    if len(text) <= SECTION_CAP and id(node) not in marked:
        return [(_label(node), 'block', text)]
    pieces = []
    loose = ' '.join(' '.join(str(c).split()) for c in node.children
                     if isinstance(c, NavigableString) and str(c).strip()).strip()
    for run in runs:
        if _qualifying(run):
            pieces.append(_listing(run))
        else:
            for kid in run:
                pieces.extend(_pieces(kid, marked))
    if loose and (not kids or len(loose) >= SECTION_MIN_CHARS):
        pieces.extend((_label(node), 'window', w) for w in window_split(loose))
    if not pieces and len(text) > SECTION_CAP:
        pieces = [(_label(node), 'window', w) for w in window_split(text)]
    return pieces


def _merge(chunks):
    """Greedy: adjacent small chunks share one, up to SECTION_CAP. Runs after
    boilerplate removal, so template text never glues itself to page content."""
    merged = []
    for chunk in chunks:
        if merged:
            prev = merged[-1]
            small = len(prev['text']) < SECTION_MIN_CHARS or len(chunk['text']) < SECTION_MIN_CHARS
            if small and prev['kind'] == chunk['kind'] == 'block' \
                    and len(prev['text']) + 1 + len(chunk['text']) <= SECTION_CAP:
                text = prev['text'] + ' ' + chunk['text']
                merged[-1] = {'label': prev['label'] or chunk['label'], 'kind': 'block',
                              'text': text, 'hash': chunk_hash(text)}
                continue
        merged.append(chunk)
    return merged


def post_clean(soup):
    """Run after chrome tags are removed. -> {'chunks', 'forms', 'links'}."""
    root = soup.find('main') or soup.find(attrs={'role': 'main'}) or soup.find('article') or soup.body or soup
    chunks = [{'label': label, 'kind': kind, 'text': text, 'hash': chunk_hash(text)}
              for label, kind, text in _pieces(root, _mark_listings(root))]
    return {'chunks': chunks, 'forms': structured_forms(soup), 'links': raw_links(soup)}


# ---------------------------------------------------------------------------
# Layer 2 + page assembly
# ---------------------------------------------------------------------------
def select(chunks, boilerplate=()):
    """Drop template chunks, then fit the rest to the page budget.

    -> {'text', 'lead', 'sections', 'outline', 'boilerplate_dropped', 'sections_dropped'}.
    A page whose cleaned text fits PAGE_EMBED_CAP is held whole (`text`, no
    sections). Otherwise `sections` holds up to MAX_SECTIONS_PER_PAGE chunks, the
    longest kept and document order preserved."""
    kept = _merge([c for c in chunks if c['hash'] not in boilerplate])
    text = ' '.join(c['text'] for c in kept)
    result = {'text': '', 'lead': text[:LEAD_CHARS], 'sections': [],
              'outline': [c['label'] for c in kept if c['label']][:16],
              'boilerplate_dropped': sum(1 for c in chunks if c['hash'] in boilerplate),
              'sections_dropped': 0}
    if len(text) <= PAGE_EMBED_CAP:
        result['text'] = text
        return result
    ranked = sorted(range(len(kept)), key=lambda i: (-len(kept[i]['text']), i))[:MAX_SECTIONS_PER_PAGE]
    keep = sorted(ranked)
    result['sections'] = [dict(kept[i], ord=n) for n, i in enumerate(keep)]
    result['sections_dropped'] = len(kept) - len(keep)
    return result
