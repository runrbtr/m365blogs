#!/usr/bin/env python3
"""Post Stream: fetch new posts from five blogs and build one page.

    python3 build.py        fetch new posts and rebuild the page once

The web app (app.py) calls build() on a timer and serves the result behind a login.
Posts are kept in archive.json, so the site keeps growing even after a blog's own feed
has scrolled past them. Only the five blogs listed in SOURCES are contacted. Standard library only.
"""
from __future__ import annotations

import concurrent.futures as cf
import functools
import hashlib
import html
import json
import os
import re
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get("DATA_DIR", ROOT / "data"))   # archive, generated page and (in app.py) the user database
SITE = DATA / "site"
ARCHIVE = DATA / "archive.json"
ASSETS = ROOT / "assets"
UA = "Mozilla/5.0 (compatible; PostStream/1.0; personal feed reader)"

BACKFILL = 100        # first run: fetch at least this many posts per blog (10 per feed page)
MAX_PAGES = 40        # hard stop for paging a single feed
PAGE_DELAY = 0.4      # seconds between page requests to the same blog
SHOW_LIMIT = 2000     # newest posts rendered on the page (archive.json keeps everything)


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    home: str   # what a human opens
    feed: str   # WordPress RSS feed, paged with ?paged=N


SOURCES = [
    Source("vanderwoude", "Peter van der Woude", "https://petervanderwoude.nl/", "https://petervanderwoude.nl/feed/"),
    Source("patchmypc", "Patch My PC", "https://patchmypc.com/blog/", "https://patchmypc.com/blog/feed/"),
    Source("staylor", "Andrew Taylor", "https://andrewstaylor.com/", "https://andrewstaylor.com/feed/"),
    Source("prajwal", "Prajwal Desai", "https://www.prajwaldesai.com/blog/", "https://www.prajwaldesai.com/feed/"),
    Source("call4cloud", "Call4Cloud", "https://call4cloud.nl/", "https://call4cloud.nl/feed/"),
    Source("htmd", "HTMD", "https://www.anoopcnair.com/", "https://www.anoopcnair.com/feed/"),
    Source("lazyadmin", "The Lazy Administrator", "https://www.thelazyadministrator.com/", "https://www.thelazyadministrator.com/feed/"),
    Source("woshub", "WOSHUB", "https://woshub.com/", "https://woshub.com/feed/"),
    Source("c7solutions", "C7 Solutions", "https://c7solutions.com/", "https://c7solutions.com/feed/"),
]
BY_ID = {s.id: s for s in SOURCES}
ORDER = {s.id: i for i, s in enumerate(SOURCES)}


# ---------------------------------------------------------------- helpers

def fetch(url: str, timeout: int = 25) -> Optional[bytes]:
    """Return the body, or None on 404 (past the last feed page). Other failures raise."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Encoding": "identity"})
    last: Optional[Exception] = None
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            last = e
        except Exception as e:  # noqa: BLE001
            last = e
        time.sleep(1 + attempt)
    raise last  # type: ignore[misc]


_TAG = re.compile(r"<[^>]+>")


def text(fragment: str) -> str:
    """HTML fragment -> plain text. Feed content is untrusted and is never rendered as HTML."""
    fragment = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", fragment or "")
    fragment = re.sub(r"(?i)</?(p|div|br|li|tr|td|h[1-6])\b[^>]*>", " ", fragment)
    return " ".join(html.unescape(_TAG.sub("", fragment)).split())


_BOILERPLATE = (
    # HTMD's feed carries no real content, just this canned CTA on every single post.
    r"Hello\s*-\s*Here is the new HTMD Blog Article.*?linkedin\.com/company/how-to-manage-devices/?",
)


def excerpt(s: str, n: int = 260) -> str:
    """Trim to a short teaser; add an ellipsis only when the text was actually cut."""
    s = re.sub(r"\s*The post .{0,300}? appeared first on .*$", "", s.strip(), flags=re.S)
    for pat in _BOILERPLATE:
        s = re.sub(pat, "", s, flags=re.S | re.I).strip()
    trimmed = re.sub(r"\s*(\[…\]|\[&hellip;\]|\.\.\.|…)\s*$", "", s)
    cut = trimmed != s
    if len(trimmed) > n:
        trimmed, cut = trimmed[:n].rsplit(" ", 1)[0], True
    if not cut:
        return trimmed.strip()
    trimmed = trimmed.rstrip(",;:. ")
    return trimmed + "…" if trimmed else ""


def clean_url(u: str) -> str:
    """Drop tracking parameters and fragments so one post has one URL."""
    p = urlsplit((u or "").strip())
    if p.scheme not in ("http", "https"):
        return ""
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not k.lower().startswith("utm_")]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), ""))


def parse_date(s: Optional[str]) -> Optional[datetime]:
    if not s or not s.strip():
        return None
    s = s.strip()
    try:
        d = parsedate_to_datetime(re.sub(r"\sZ$", " +0000", s))
    except (TypeError, ValueError, IndexError):
        try:
            d = datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", s.replace("Z", "+00:00")))
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def norm_title(t: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", t.lower()).strip()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_write(path: Path, content: str) -> None:
    """Write via a temp file so a reader never sees a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def asset_url(name: str) -> str:
    """Relative URL of a static asset with a content hash, so browsers refetch it when it changes."""
    digest = hashlib.sha1((ASSETS / name).read_bytes()).hexdigest()[:8]
    return f"static/{name}?v={digest}"


# ---------------------------------------------------------------- fetching

def parse_feed(data: bytes, src: Source) -> list:
    root = ET.fromstring(data.lstrip())  # some feeds (e.g. c7solutions) emit stray bytes before <?xml ...?>
    posts = []
    for it in root.iter("item"):
        f, tags = {}, []
        for c in it:
            n = c.tag.rsplit("}", 1)[-1]
            if n == "category":
                if c.text and c.text.strip():
                    tags.append(text(c.text))
            elif n not in f:
                f[n] = c.text or ""
        url, title, date = clean_url(f.get("link", "")), text(f.get("title", "")), parse_date(f.get("pubDate"))
        if not (url and title and date):
            continue
        body = f.get("description") or f.get("encoded") or ""
        posts.append({
            "url": url, "title": title, "sources": [src.id], "date": date.isoformat(),
            "summary": excerpt(text(body)), "tags": tags[:4], "author": text(f.get("creator", "")),
        })
    return posts


def update_source(src: Source, archive: dict) -> dict:
    """Page through one feed until it is caught up (and, on first run, backfilled)."""
    have = {u for u, p in archive["posts"].items() if src.id in p["sources"]}
    first_run = not have
    added, page = [], 1
    while page <= MAX_PAGES:
        data = fetch(src.feed if page == 1 else f"{src.feed}?paged={page}")
        batch = parse_feed(data, src) if data else []
        if not batch:
            break                                   # past the last feed page
        fresh = [p for p in batch if p["url"] not in have]
        have.update(p["url"] for p in fresh)
        added += fresh
        if first_run:
            if len(have) >= BACKFILL:
                break                               # enough history for a first run
        elif not fresh:
            break                                   # caught up with what we already have
        page += 1
        time.sleep(PAGE_DELAY)
    stamp = now_iso()
    for p in added:
        # Backfilled history counts as already published, not as newly seen.
        p["first_seen"] = p["date"] if first_run else stamp
    return {"posts": added}


def refresh() -> dict:
    DATA.mkdir(parents=True, exist_ok=True)
    legacy = ROOT / "archive.json"          # location used before the data directory existed
    if legacy.exists() and not ARCHIVE.exists() and DATA != ROOT:
        os.replace(legacy, ARCHIVE)
    archive = json.loads(ARCHIVE.read_text()) if ARCHIVE.exists() else {"posts": {}, "sources": {}}
    archive.setdefault("sources", {})

    def job(src: Source):
        try:
            return src.id, update_source(src, archive), None
        except Exception as e:  # noqa: BLE001 - one broken blog must not stop the others
            return src.id, {"posts": []}, f"{type(e).__name__}: {e}"[:200]

    with cf.ThreadPoolExecutor(len(SOURCES)) as ex:
        for sid, res, err in ex.map(job, SOURCES):
            for p in res["posts"]:
                old = archive["posts"].get(p["url"])
                if old is None:
                    archive["posts"][p["url"]] = p
                else:                      # same URL served by another blog's feed: one post, several sources
                    old["sources"] += [x for x in p["sources"] if x not in old["sources"]]
                    old["first_seen"] = min(old["first_seen"], p["first_seen"])
            st = archive["sources"].setdefault(sid, {})
            st["error"] = err
            st["new"] = len(res["posts"])
            if not err:
                st["last_ok"] = now_iso()
    atomic_write(ARCHIVE, json.dumps(archive, indent=1, ensure_ascii=False))
    return archive


# ---------------------------------------------------------------- merge cross-posts

def merged_posts(archive: dict) -> list:
    """One entry per article. Copies of an article on different URLs are merged, earliest copy first."""
    groups: dict = {}
    for p in archive["posts"].values():
        groups.setdefault(norm_title(p["title"]), []).append(p)
    out = []
    for copies in groups.values():
        copies.sort(key=lambda p: (p["date"], ORDER[p["sources"][0]]))
        first = dict(copies[0])
        first["sources"] = sorted({x for c in copies for x in c["sources"]}, key=ORDER.get)
        first["also"] = [{"source": c["sources"][0], "url": c["url"]} for c in copies[1:]]
        first["first_seen"] = min(c["first_seen"] for c in copies)
        out.append(first)
    out.sort(key=lambda p: p["date"], reverse=True)
    return out


# ---------------------------------------------------------------- rendering

esc = functools.partial(html.escape, quote=True)

STAR = ('<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" focusable="false"><path d="M12 2.8l2.9 6 6.6.9-4.8 4.6 '
        '1.2 6.5L12 17.6l-5.9 3.2 1.2-6.5L2.5 9.7l6.6-.9z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>')


def fmt_day(d: datetime) -> str:
    return f"{d.strftime('%A')}, {d.day} {d.strftime('%B %Y')}"


def render_post(p: dict) -> str:
    d = parse_date(p["date"])
    chips = "".join(
        f'<span class="chip" data-s="{ORDER[s]}">{esc(BY_ID[s].name)}</span>' for s in p["sources"])
    also = "".join(
        f'<a class="also" href="{esc(a["url"])}" target="_blank" rel="noopener noreferrer">also on {esc(BY_ID[a["source"]].name)} ↗</a>'
        for a in p["also"])
    tags = "".join(f'<span class="tag">{esc(t)}</span>' for t in p["tags"][:3])
    summary = f'<p class="snip">{esc(p["summary"])}</p>' if p["summary"] else ""
    names = {BY_ID[x].name.lower() for x in p["sources"]}
    author = f'<span>{esc(p["author"])}</span>' if p["author"] and p["author"].lower() not in names else ""
    return (f'<article class="post" data-src="{" ".join(p["sources"])}" data-first="{esc(p["first_seen"])}" data-url="{esc(p["url"])}">'
            f'<button class="star" type="button" aria-pressed="false">{STAR}</button>'
            f'<h3><a href="{esc(p["url"])}" target="_blank" rel="noopener noreferrer">{esc(p["title"])}</a></h3>'
            f'<div class="meta">{chips}{also}{author}<time datetime="{d.isoformat()}">{d.strftime("%H:%M")} UTC</time></div>'
            f'{summary}<div class="tags">{tags}</div></article>')


def render_page(archive: dict, posts: list) -> str:
    shown = posts[:SHOW_LIMIT]
    days, current = [], None
    for p in shown:
        d = parse_date(p["date"])
        key = d.date().isoformat()
        if key != current:
            days.append([fmt_day(d), []])
            current = key
        days[-1][1].append(render_post(p))
    body = "".join(f'<section class="day"><h2>{esc(label)}</h2>{"".join(items)}</section>' for label, items in days)

    counts = {s.id: sum(1 for p in posts if s.id in p["sources"]) for s in SOURCES}
    chips = "".join(
        f'<button class="fchip" type="button" data-s="{ORDER[s.id]}" data-id="{s.id}" aria-pressed="false">'
        f'{esc(s.name)} <span class="n">{counts[s.id]}</span></button>' for s in SOURCES)

    problems = [f'{BY_ID[k].name}' for k, v in archive["sources"].items() if v.get("error")]
    warn = (f'<div class="banner warn" role="status">Could not check {esc(", ".join(problems))} on the last refresh. '
            f'Showing what was already archived.</div>') if problems else ""

    rows = []
    for s in SOURCES:
        mine = [p for p in posts if s.id in p["sources"]]
        st = archive["sources"].get(s.id, {})
        newest = parse_date(mine[0]["date"]).strftime("%b %d, %Y") if mine else "-"
        status = f'<span class="bad">error</span>' if st.get("error") else '<span class="ok">ok</span>'
        rows.append(f'<tr><td><a href="{esc(s.home)}" target="_blank" rel="noopener noreferrer">{esc(s.name)} ↗</a></td>'
                    f'<td>{counts[s.id]}</td><td>{newest}</td><td>{status}</td>'
                    f'<td><a href="{esc(s.feed)}" target="_blank" rel="noopener noreferrer">feed</a></td></tr>')

    now = datetime.now(timezone.utc)
    return f"""<!doctype html>
<html lang="en" data-generated="{now.isoformat()}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>M365Blogs</title>
<link rel="icon" type="image/svg+xml" href="{asset_url("icon.svg")}">
<meta name="robots" content="noindex, nofollow">
<meta name="description" content="Every new post from Peter van der Woude, Patch My PC, Andrew Taylor, Prajwal Desai and Call4Cloud in one place.">
<link rel="stylesheet" href="{asset_url("style.css")}">
<script src="{asset_url("app.js")}" defer></script>
</head>
<body>
<header class="top"><div class="wrap">
  <div class="titlerow">
    <h1>M365Blogs</h1>
    <div class="account">
      <span id="whoami" hidden></span>
      <form id="logout" method="post" action="logout" hidden><button class="linkbtn" type="submit">Sign out</button></form>
      <span id="guest" hidden><a href="login">Sign in</a> · <a href="signup">Create account</a></span>
    </div>
  </div>
  <p class="sub">Every new post from {len(SOURCES)} blogs, newest first. Titles link to the original.</p>
  <p class="checked">Checked <time datetime="{now.isoformat()}">{now.strftime("%b %d, %H:%M UTC")}</time></p>
  <label class="search"><span class="sr">Search posts</span>
    <input id="q" type="search" placeholder="Search posts (press /)" autocomplete="off"></label>
  <div class="filters" role="group" aria-label="Filter posts">
    <button class="fchip favchip" id="favchip" type="button" aria-pressed="false">★ Favorites <span class="n">0</span></button>{chips}</div>
</div></header>
<main class="wrap">
{warn}
<div id="stale" class="banner warn" role="status" hidden></div>
<div id="apierr" class="banner warn" role="alert" hidden></div>
<div id="unread" class="banner" role="status" hidden><span id="unread-text"></span> <button id="markread" type="button">Mark all as read</button></div>
<p id="count" class="count" aria-live="polite"></p>
{body}
<p id="nomatch" class="empty" hidden>No posts match.</p>
<section class="sources"><h2>Sources</h2>
<table><thead><tr><th>Blog</th><th>Posts</th><th>Newest</th><th>Status</th><th></th></tr></thead><tbody>{"".join(rows)}</tbody></table>
<p class="note">{len(posts)} posts archived{f" ({SHOW_LIMIT} newest shown)" if len(posts) > SHOW_LIMIT else ""}.
Posts published on more than one blog appear once, with a link to the other copy.</p></section>
</main>
</body>
</html>
"""


def build() -> dict:
    """Fetch new posts, rebuild the page and return the archive."""
    started = time.time()
    archive = refresh()
    posts = merged_posts(archive)
    atomic_write(SITE / "index.html", render_page(archive, posts))
    new = sum(v.get("new", 0) for v in archive["sources"].values())
    bad = [f"{k} ({v['error']})" for k, v in archive["sources"].items() if v.get("error")]
    print(f"[{datetime.now():%H:%M:%S}] {new} new posts, {len(posts)} articles archived, built in {time.time() - started:.1f}s"
          + (f"; failed: {'; '.join(bad)}" if bad else ""), flush=True)
    return archive


if __name__ == "__main__":
    build()
