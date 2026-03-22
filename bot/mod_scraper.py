"""
Mod Scraper — Downloads Minecraft mod JARs from multiple sources.
Integrated with RATScanner for automatic batch scanning.

Sources: Modrinth, CurseForge, PlanetMinecraft, NexusMods, Hangar
Sort: Most downloaded first (where API supports it)
"""
import asyncio
import aiofiles
import aiohttp
import json
import logging
import os
import re
import shutil
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import AsyncGenerator, Optional

try:
    from bs4 import BeautifulSoup
    BS4_OK = True
except ImportError:
    BS4_OK = False

try:
    from curl_cffi.requests import AsyncSession as CurlSession
    HAS_CURL = True
except ImportError:
    HAS_CURL = False

log = logging.getLogger("scraper")

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
DOWNLOAD_TIMEOUT = 180
RETRY_COUNT = 3
RETRY_DELAY = 5

RATE_LIMITS = {
    "modrinth": 5,
    "curseforge": 3,
    "planetminecraft": 1,
    "nexusmods": 1,
    "hangar": 3,
}

# API endpoints
MR_BASE = "https://api.modrinth.com/v2"
CF_BASE = "https://api.curseforge.com"
CF_GAME_ID = 432
CF_CLASS_MODS = 6
NX_BASE = "https://api.nexusmods.com/v1"
NX_GAME = "minecraft"
HANGAR_BASE = "https://hangar.papermc.io/api/v1"
PMC = "https://www.planetminecraft.com"


# ── Data Classes ──────────────────────────────────────────────────────────────

class ModInfo:
    def __init__(self, source, source_id, name, slug=None, author=None, downloads=0):
        self.source = source
        self.source_id = str(source_id)
        self.name = name
        self.slug = slug
        self.author = author
        self.downloads = downloads


class FileInfo:
    def __init__(self, source, file_id, filename, url, size=None):
        self.source = source
        self.file_id = str(file_id)
        self.filename = filename
        self.url = url
        self.size = size


# ── Base Scraper ──────────────────────────────────────────────────────────────

class BaseScraper(ABC):
    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 1.0):
        self.session = session
        self.rate_limit = rate_limit
        self._last_req = 0.0

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    async def iter_mods(self, offset: int = 0) -> AsyncGenerator[ModInfo, None]: ...

    @abstractmethod
    async def get_files(self, mod: ModInfo) -> list[FileInfo]: ...

    async def _wait(self):
        if self.rate_limit <= 0:
            return
        gap = 1.0 / self.rate_limit
        elapsed = time.monotonic() - self._last_req
        if elapsed < gap:
            await asyncio.sleep(gap - elapsed)
        self._last_req = time.monotonic()

    async def _get_json(self, url, headers=None, params=None) -> Optional[dict]:
        await self._wait()
        for attempt in range(RETRY_COUNT):
            try:
                async with self.session.get(url, headers=headers, params=params,
                        timeout=aiohttp.ClientTimeout(total=DOWNLOAD_TIMEOUT)) as r:
                    if r.status == 200:
                        return await r.json()
                    if r.status == 429:
                        raw_retry = r.headers.get("Retry-After", "30")
                        try:
                            wait = int(raw_retry)
                        except (ValueError, TypeError):
                            wait = 30
                        log.warning(f"[{self.name}] 429, waiting {wait}s")
                        await asyncio.sleep(wait)
                        continue
                    if r.status in (401, 403):
                        log.warning(f"[{self.name}] Auth error {r.status}: {url}")
                        return None  # Don't retry auth failures
                    if r.status in (404, 410):
                        return None
                    log.warning(f"[{self.name}] HTTP {r.status}: {url}")
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                log.warning(f"[{self.name}] Req err ({attempt+1}): {e}")
            if attempt < RETRY_COUNT - 1:
                await asyncio.sleep(RETRY_DELAY * (attempt + 1))
        return None

    async def _get_html(self, url, headers=None) -> Optional[str]:
        await self._wait()
        for attempt in range(RETRY_COUNT):
            try:
                async with self.session.get(url, headers=headers,
                        timeout=aiohttp.ClientTimeout(total=DOWNLOAD_TIMEOUT)) as r:
                    if r.status == 200:
                        return await r.text()
                    if r.status == 429:
                        raw_retry = r.headers.get("Retry-After", "30")
                        try:
                            retry_wait = int(raw_retry)
                        except (ValueError, TypeError):
                            retry_wait = 30
                        await asyncio.sleep(retry_wait)
                        continue
                    if r.status in (401, 403):
                        log.warning(f"[{self.name}] Auth error {r.status}: {url}")
                        return None
                    if r.status in (404, 410):
                        return None
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                log.warning(f"[{self.name}] Req err ({attempt+1}): {e}")
            if attempt < RETRY_COUNT - 1:
                await asyncio.sleep(RETRY_DELAY * (attempt + 1))
        return None

    async def download(self, file_info: FileInfo, dest: Path) -> bool:
        if file_info.size and file_info.size > MAX_FILE_SIZE:
            return False
        # Only allow http/https downloads (block file://, ftp://, etc.)
        if not file_info.url.startswith(("https://", "http://")):
            log.warning(f"[{self.name}] Blocked non-HTTP URL: {file_info.url[:100]}")
            return False
        await self._wait()
        dest.parent.mkdir(parents=True, exist_ok=True)
        for attempt in range(RETRY_COUNT):
            try:
                async with self.session.get(file_info.url,
                        timeout=aiohttp.ClientTimeout(total=DOWNLOAD_TIMEOUT * 2)) as r:
                    if r.status != 200:
                        if r.status == 429:
                            raw_retry = r.headers.get("Retry-After", "30")
                            try:
                                retry_wait = int(raw_retry)
                            except (ValueError, TypeError):
                                retry_wait = 30
                            await asyncio.sleep(retry_wait)
                            continue
                        if r.status in (401, 403):
                            log.warning(f"[{self.name}] Auth error {r.status} downloading: {file_info.url[:100]}")
                            return False
                        if attempt < RETRY_COUNT - 1:
                            await asyncio.sleep(RETRY_DELAY * (attempt + 1))
                        continue
                    cl = r.headers.get("Content-Length")
                    if cl and cl.isdigit() and int(cl) > MAX_FILE_SIZE:
                        return False
                    total = 0
                    oversize = False
                    async with aiofiles.open(dest, "wb") as f:
                        async for chunk in r.content.iter_chunked(8192):
                            total += len(chunk)
                            if total > MAX_FILE_SIZE:
                                oversize = True
                                break
                            await f.write(chunk)
                    if oversize:
                        dest.unlink(missing_ok=True)
                        return False
                    return True
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                log.warning(f"[{self.name}] DL err ({attempt+1}): {e}")
                dest.unlink(missing_ok=True)
                if attempt < RETRY_COUNT - 1:
                    await asyncio.sleep(RETRY_DELAY * (attempt + 1))
        return False


# ── Modrinth ──────────────────────────────────────────────────────────────────

class ModrinthScraper(BaseScraper):
    def __init__(self, session):
        super().__init__(session, RATE_LIMITS["modrinth"])
        self._h = {"User-Agent": "RATScanner/1.0 (mod-scanning-project)"}

    @property
    def name(self):
        return "modrinth"

    async def iter_mods(self, offset=0) -> AsyncGenerator[ModInfo, None]:
        limit = 100
        off = offset
        while True:
            data = await self._get_json(f"{MR_BASE}/search", headers=self._h, params={
                "facets": json.dumps([["project_type:mod"]]),
                "limit": limit, "offset": off, "index": "downloads",
            })
            if not data or not data.get("hits"):
                break
            for h in data["hits"]:
                yield ModInfo(
                    source="modrinth", source_id=h["project_id"],
                    name=h["title"], slug=h.get("slug"),
                    author=h.get("author"),
                    downloads=h.get("downloads", 0),
                )
            total = data.get("total_hits", 0)
            off += limit
            if off >= total:
                break

    async def get_files(self, mod: ModInfo) -> list[FileInfo]:
        data = await self._get_json(
            f"{MR_BASE}/project/{mod.source_id}/version", headers=self._h)
        if not data:
            return []
        files = []
        for ver in data:
            for f in ver.get("files", []):
                if f["filename"].endswith(".jar"):
                    files.append(FileInfo(
                        source="modrinth",
                        file_id=f.get("hashes", {}).get("sha1", ver["id"]),
                        filename=f["filename"], url=f["url"],
                        size=f.get("size"),
                    ))
        return files


# ── CurseForge ────────────────────────────────────────────────────────────────

class CurseForgeScraper(BaseScraper):
    """Scrapes CurseForge using curl_cffi (bypasses Cloudflare) + internal web API."""

    def __init__(self, session, api_key=""):
        super().__init__(session, RATE_LIMITS["curseforge"])
        self._api_key = api_key
        self._h = {"Accept": "application/json", "x-api-key": api_key}
        self._curl = None
        self._use_web = not api_key or not HAS_CURL  # Fall back to web scraping if no key

    def _ensure_curl(self):
        if self._curl is None and HAS_CURL:
            self._curl = CurlSession(impersonate="chrome124")
        return self._curl

    @property
    def name(self):
        return "curseforge"

    async def iter_mods(self, offset=0) -> AsyncGenerator[ModInfo, None]:
        # Try official API first
        if self._api_key:
            async for mod in self._iter_mods_api(offset):
                yield mod
            return
        # Fallback: scrape web listing with curl_cffi
        if not HAS_CURL or not BS4_OK:
            log.warning("No CurseForge API key and no curl_cffi/bs4, skipping")
            return
        async for mod in self._iter_mods_web(offset):
            yield mod

    async def _iter_mods_api(self, offset=0) -> AsyncGenerator[ModInfo, None]:
        page_size = 50
        idx = offset
        while True:
            data = await self._get_json(f"{CF_BASE}/v1/mods/search", headers=self._h,
                params={
                    "gameId": CF_GAME_ID, "classId": CF_CLASS_MODS,
                    "sortField": 2, "sortOrder": "desc",
                    "pageSize": page_size, "index": idx,
                })
            if not data or not data.get("data"):
                # API key might be invalid — skip web scraping (curl_cffi blocks event loop)
                if idx == offset:
                    log.warning("[curseforge] API key rejected, skipping CurseForge (web scraping disabled — blocks event loop)")
                    self._api_key = ""
                return
            for m in data["data"]:
                authors = m.get("authors", [])
                yield ModInfo(
                    source="curseforge", source_id=str(m["id"]),
                    name=m["name"], slug=m.get("slug"),
                    author=authors[0]["name"] if authors else None,
                    downloads=m.get("downloadCount", 0),
                )
            total = data.get("pagination", {}).get("totalCount", 0)
            idx += page_size
            if idx >= total:
                break

    async def _iter_mods_web(self, offset=0) -> AsyncGenerator[ModInfo, None]:
        """Scrape mod listings from the CurseForge website."""
        curl = self._ensure_curl()
        if not curl:
            return
        page = max(1, (offset // 20) + 1)
        while True:
            await self._wait()
            try:
                r = await asyncio.wait_for(
                    curl.get(
                        f"https://www.curseforge.com/minecraft/mc-mods?page={page}&pageSize=20&sortBy=popularity",
                        timeout=DOWNLOAD_TIMEOUT, allow_redirects=True),
                    timeout=DOWNLOAD_TIMEOUT + 10)
                if r.status_code != 200:
                    log.warning(f"[curseforge] Web listing HTTP {r.status_code}")
                    break
            except asyncio.TimeoutError:
                log.warning("[curseforge] Web listing timed out (asyncio)")
                break
            except Exception as e:
                log.warning(f"[curseforge] Web listing error: {e}")
                break
            soup = BeautifulSoup(r.text, "html.parser")
            seen = set()
            found_any = False
            for a in soup.select('a[href*="/minecraft/mc-mods/"]'):
                href = a.get("href", "")
                m = re.match(r'/minecraft/mc-mods/([a-z0-9-]+)$', href)
                if not m or m.group(1) in seen:
                    continue
                slug = m.group(1)
                seen.add(slug)
                found_any = True
                # Get project ID from mod page
                pid = await self._get_project_id(slug)
                if not pid:
                    continue
                name = a.get_text(strip=True) or slug
                yield ModInfo(
                    source="curseforge", source_id=pid,
                    name=name, slug=slug,
                )
            if not found_any:
                break
            page += 1

    async def _get_project_id(self, slug: str) -> Optional[str]:
        """Extract project ID from a CurseForge mod page."""
        curl = self._ensure_curl()
        if not curl:
            return None
        await self._wait()
        try:
            r = await asyncio.wait_for(
                curl.get(f"https://www.curseforge.com/minecraft/mc-mods/{slug}",
                         timeout=DOWNLOAD_TIMEOUT, allow_redirects=True),
                timeout=DOWNLOAD_TIMEOUT + 10)
            if r.status_code != 200:
                return None
            m = re.search(r'project[_-]?[iI]d[^0-9]*(\d+)', r.text)
            return m.group(1) if m else None
        except asyncio.TimeoutError:
            log.warning(f"[curseforge] Project ID fetch timed out: {slug}")
            return None
        except Exception:
            return None

    async def get_files(self, mod: ModInfo) -> list[FileInfo]:
        files = []
        idx = 0
        page_size = 50
        # Use internal web API (works without API key via curl_cffi)
        use_internal = bool(self._ensure_curl())
        while True:
            if use_internal:
                await self._wait()
                try:
                    r = await asyncio.wait_for(
                        self._curl.get(
                            f"https://www.curseforge.com/api/v1/mods/{mod.source_id}/files",
                            params={"pageSize": page_size, "index": idx},
                            timeout=DOWNLOAD_TIMEOUT),
                        timeout=DOWNLOAD_TIMEOUT + 10)
                    if r.status_code != 200:
                        break
                    data = {"data": r.json().get("data", [])}
                    data["pagination"] = r.json().get("pagination", {})
                except Exception:
                    break
            else:
                data = await self._get_json(
                    f"{CF_BASE}/v1/mods/{mod.source_id}/files",
                    headers=self._h, params={"pageSize": page_size, "index": idx})
            if not data or not data.get("data"):
                break
            for f in data["data"]:
                fname = f.get("fileName", "")
                if not fname.endswith(".jar"):
                    continue
                if f.get("isServerPack") or f.get("hasServerPack"):
                    continue
                fid = f["id"]
                # Build CDN download URL
                id1 = fid // 1000
                id2 = fid % 1000
                url = f.get("downloadUrl") or f"https://edge.forgecdn.net/files/{id1}/{id2}/{fname}"
                files.append(FileInfo(
                    source="curseforge", file_id=str(fid),
                    filename=fname, url=url,
                    size=f.get("fileLength"),
                ))
            total = data.get("pagination", {}).get("totalCount", 0)
            idx += page_size
            if idx >= total:
                break
        return files

    async def download(self, file_info: FileInfo, dest: Path) -> bool:
        """Download from CurseForge CDN using curl_cffi."""
        curl = self._ensure_curl()
        if not curl:
            return await super().download(file_info, dest)
        if not file_info.url.startswith(("https://", "http://")):
            return False
        await self._wait()
        dest.parent.mkdir(parents=True, exist_ok=True)
        for attempt in range(RETRY_COUNT):
            try:
                r = await asyncio.wait_for(
                    curl.get(file_info.url, timeout=DOWNLOAD_TIMEOUT * 2, allow_redirects=True),
                    timeout=DOWNLOAD_TIMEOUT * 2 + 10)
                if r.status_code in (401, 403):
                    log.warning(f"[{self.name}] Auth error {r.status_code}: {file_info.url[:100]}")
                    return False
                if r.status_code != 200:
                    if attempt < RETRY_COUNT - 1:
                        await asyncio.sleep(RETRY_DELAY * (attempt + 1))
                    continue
                content = r.content
                if len(content) > MAX_FILE_SIZE:
                    return False
                async with aiofiles.open(dest, "wb") as f:
                    await f.write(content)
                return True
            except Exception as e:
                log.warning(f"[{self.name}] Download error ({attempt+1}): {e}")
            if attempt < RETRY_COUNT - 1:
                await asyncio.sleep(RETRY_DELAY * (attempt + 1))
        return False


# ── PlanetMinecraft ───────────────────────────────────────────────────────────

class PlanetMinecraftScraper(BaseScraper):
    def __init__(self, session):
        super().__init__(session, RATE_LIMITS["planetminecraft"])
        self._h = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"}
        self._curl = None

    async def _curl_get_html(self, url: str) -> Optional[str]:
        """Fetch HTML using curl_cffi to bypass Cloudflare."""
        if not HAS_CURL:
            return await self._get_html(url, headers=self._h)
        if self._curl is None:
            self._curl = CurlSession(impersonate="chrome124")
        await self._wait()
        for attempt in range(RETRY_COUNT):
            try:
                r = await asyncio.wait_for(
                    self._curl.get(url, timeout=DOWNLOAD_TIMEOUT, allow_redirects=True),
                    timeout=DOWNLOAD_TIMEOUT + 10)
                if r.status_code == 200:
                    return r.text
                if r.status_code in (401, 403):
                    log.warning(f"[{self.name}] Auth error {r.status_code}: {url}")
                    return None
                if r.status_code in (404, 410):
                    return None
                if r.status_code == 429:
                    await asyncio.sleep(30)
                    continue
                log.warning(f"[{self.name}] curl HTTP {r.status_code}: {url}")
            except Exception as e:
                log.warning(f"[{self.name}] curl error ({attempt+1}): {e}")
            if attempt < RETRY_COUNT - 1:
                await asyncio.sleep(RETRY_DELAY * (attempt + 1))
        return None

    @property
    def name(self):
        return "planetminecraft"

    async def iter_mods(self, offset=0) -> AsyncGenerator[ModInfo, None]:
        if not BS4_OK:
            log.warning("bs4 not installed, skipping PlanetMinecraft")
            return
        page = max(1, (offset // 25) + 1)
        while True:
            html = await self._curl_get_html(
                f"{PMC}/mods/minecraft-java-edition/?order=order_popularity&p={page}")
            if not html:
                break
            soup = BeautifulSoup(html, "html.parser")
            items = soup.select("div.r-info")
            if not items:
                break
            for item in items:
                link = item.select_one("a.r-title") or item.select_one("a[href*='/mod/']")
                if not link:
                    continue
                name = link.get_text(strip=True)
                href = link.get("href", "")
                lower = name.lower() + " " + href.lower()
                if "modpack" in lower or "mod-pack" in lower:
                    continue
                id_m = re.search(r'/mod/[^/]*?(\d+)/', href) or \
                       re.search(r'/mod/([^/]+)/', href)
                sid = id_m.group(1) if id_m else href
                yield ModInfo(
                    source="planetminecraft", source_id=sid,
                    name=name, slug=href.rstrip("/").split("/")[-1],
                )
            nxt = soup.select_one("a.next_page") or soup.select_one("a[rel='next']")
            if not nxt:
                break
            page += 1

    async def get_files(self, mod: ModInfo) -> list[FileInfo]:
        if not BS4_OK:
            return []
        from urllib.parse import urljoin
        files = []
        url = f"{PMC}/mod/{mod.slug}/" if mod.slug else f"{PMC}/mod/{mod.source_id}/"
        html = await self._curl_get_html(url)
        if not html:
            return files
        soup = BeautifulSoup(html, "html.parser")
        dls = soup.select("a.download-link, a[href*='/download/'], a.res_download")
        for i, dl in enumerate(dls):
            href = dl.get("href", "")
            if not href:
                continue
            furl = urljoin(PMC, href)
            # PMC download URLs end in /download/file/ID/ — use mod slug for filename
            fname = f"{mod.slug or mod.source_id}.jar"
            files.append(FileInfo(
                source="planetminecraft",
                file_id=f"{mod.source_id}_{i}",
                filename=fname, url=furl,
            ))
        return files

    async def download(self, file_info: FileInfo, dest: Path) -> bool:
        """Download using curl_cffi to bypass Cloudflare on PMC."""
        if not HAS_CURL:
            return await super().download(file_info, dest)
        if not file_info.url.startswith(("https://", "http://")):
            log.warning(f"[{self.name}] Blocked non-HTTP URL: {file_info.url[:100]}")
            return False
        if self._curl is None:
            self._curl = CurlSession(impersonate="chrome124")
        await self._wait()
        dest.parent.mkdir(parents=True, exist_ok=True)
        for attempt in range(RETRY_COUNT):
            try:
                r = await asyncio.wait_for(
                    self._curl.get(file_info.url, timeout=DOWNLOAD_TIMEOUT * 2, allow_redirects=True),
                    timeout=DOWNLOAD_TIMEOUT * 2 + 10)
                if r.status_code in (401, 403):
                    log.warning(f"[{self.name}] Auth error {r.status_code} downloading: {file_info.url[:100]}")
                    return False
                if r.status_code != 200:
                    if attempt < RETRY_COUNT - 1:
                        await asyncio.sleep(RETRY_DELAY * (attempt + 1))
                    continue
                content = r.content
                if len(content) > MAX_FILE_SIZE:
                    return False
                async with aiofiles.open(dest, "wb") as f:
                    await f.write(content)
                return True
            except Exception as e:
                log.warning(f"[{self.name}] curl download error ({attempt+1}): {e}")
            if attempt < RETRY_COUNT - 1:
                await asyncio.sleep(RETRY_DELAY * (attempt + 1))
        return False


# ── NexusMods ─────────────────────────────────────────────────────────────────

class NexusModsScraper(BaseScraper):
    def __init__(self, session, api_key=""):
        super().__init__(session, RATE_LIMITS["nexusmods"])
        self._api_key = api_key
        self._h = {"accept": "application/json", "apikey": api_key}
        self._download_links_blocked = False  # Set True if download_link returns 403 (requires premium)

    @property
    def name(self):
        return "nexusmods"

    async def iter_mods(self, offset=0) -> AsyncGenerator[ModInfo, None]:
        if not self._api_key:
            log.warning("No NexusMods API key, skipping")
            return
        seen = set()
        for endpoint in ["updated", "latest_added"]:
            params = {"period": "1m"} if endpoint == "updated" else {}
            data = await self._get_json(
                f"{NX_BASE}/games/{NX_GAME}/mods/{endpoint}.json",
                headers=self._h, params=params)
            if not data:
                continue
            for stub in data:
                mid = stub.get("mod_id")
                if not mid or mid in seen:
                    continue
                seen.add(mid)
                detail = await self._get_json(
                    f"{NX_BASE}/games/{NX_GAME}/mods/{mid}.json",
                    headers=self._h)
                if not detail:
                    continue
                name = detail.get("name", "").lower()
                summary = detail.get("summary", "").lower()
                if "modpack" in name or "mod pack" in name or "modpack" in summary:
                    continue
                yield ModInfo(
                    source="nexusmods", source_id=str(mid),
                    name=detail.get("name", ""),
                    author=detail.get("author"),
                    downloads=detail.get("mod_downloads", 0),
                )

    async def get_files(self, mod: ModInfo) -> list[FileInfo]:
        if self._download_links_blocked:
            return []  # Premium API required for download links
        data = await self._get_json(
            f"{NX_BASE}/games/{NX_GAME}/mods/{mod.source_id}/files.json",
            headers=self._h)
        if not data or "files" not in data:
            return []
        files = []
        for f in data["files"]:
            fid = f["file_id"]
            fname = f.get("file_name", "").lower()
            if "modpack" in fname:
                continue
            dl_url = f"{NX_BASE}/games/{NX_GAME}/mods/{mod.source_id}/files/{fid}/download_link.json"
            # Check download_link endpoint — 403 means premium required
            try:
                async with self.session.get(dl_url, headers=self._h,
                        timeout=aiohttp.ClientTimeout(total=30)) as r:
                    if r.status == 403:
                        log.warning(f"[{self.name}] download_link requires premium API — skipping NexusMods downloads")
                        self._download_links_blocked = True
                        return files
                    if r.status != 200:
                        continue
                    dl = await r.json()
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
            url = None
            if dl and isinstance(dl, list) and dl:
                url = dl[0].get("URI")
            if not url:
                continue
            files.append(FileInfo(
                source="nexusmods", file_id=str(fid),
                filename=f.get("file_name", f"file_{fid}"),
                url=url,
                size=f.get("size_in_bytes") or (f.get("size_kb", 0) * 1024),
            ))
        return files


# ── Hangar ────────────────────────────────────────────────────────────────────

class HangarScraper(BaseScraper):
    def __init__(self, session):
        super().__init__(session, RATE_LIMITS["hangar"])
        self._h = {"User-Agent": "RATScanner/1.0 (mod-scanning-project)"}

    @property
    def name(self):
        return "hangar"

    async def iter_mods(self, offset=0) -> AsyncGenerator[ModInfo, None]:
        limit = 25
        off = offset
        while True:
            data = await self._get_json(f"{HANGAR_BASE}/projects",
                headers=self._h, params={
                    "limit": limit, "offset": off, "sort": "-downloads"})
            if not data or not data.get("result"):
                break
            for p in data["result"]:
                ns = p.get("namespace", {})
                stats = p.get("stats", {})
                yield ModInfo(
                    source="hangar",
                    source_id=ns.get("slug", p.get("name", "")),
                    name=p.get("name", ""),
                    slug=ns.get("slug"),
                    author=ns.get("owner"),
                    downloads=stats.get("downloads", 0),
                )
            total = data.get("pagination", {}).get("count", 0)
            off += limit
            if off >= total:
                break

    async def get_files(self, mod: ModInfo) -> list[FileInfo]:
        files = []
        limit = 25
        off = 0
        while True:
            data = await self._get_json(
                f"{HANGAR_BASE}/projects/{mod.source_id}/versions",
                headers=self._h, params={"limit": limit, "offset": off})
            if not data or not data.get("result"):
                break
            for ver in data["result"]:
                vname = ver.get("name", "")
                for platform, dl in (ver.get("downloads") or {}).items():
                    if not dl or not isinstance(dl, dict):
                        continue
                    fi = dl.get("fileInfo") or {}
                    fname = fi.get("name", f"{mod.source_id}-{vname}.jar")
                    if not fname.endswith(".jar"):
                        continue
                    url = (f"{HANGAR_BASE}/projects/{mod.source_id}"
                           f"/versions/{vname}/{platform}/download")
                    files.append(FileInfo(
                        source="hangar",
                        file_id=f"{mod.source_id}_{vname}_{platform}",
                        filename=fname, url=url,
                        size=fi.get("sizeBytes"),
                    ))
            total = data.get("pagination", {}).get("count", 0)
            off += limit
            if off >= total:
                break
        return files


# ── Progress Tracking ─────────────────────────────────────────────────────────

class ScrapeProgress:
    """Tracks scrape progress for resume support."""
    def __init__(self, progress_file: Path):
        self._file = progress_file
        self._data = self._load()
        # Build in-memory sets for O(1) lookups
        self._done_sets: dict[str, set] = {}
        for src, info in self._data.items():
            if isinstance(info, dict) and "done" in info:
                self._done_sets[src] = set(info["done"])
        self._dirty = False

    def _load(self) -> dict:
        for path in [self._file, Path(str(self._file) + ".bak")]:
            if path.exists():
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        return data
                except Exception:
                    continue
        return {}

    def _save(self):
        if not self._dirty:
            return
        try:
            # Keep a backup of the last good save
            if self._file.exists():
                bak = Path(str(self._file) + ".bak")
                try:
                    shutil.copy2(str(self._file), str(bak))
                except Exception:
                    pass
            # Atomic write via temp file
            tmp = str(self._file) + ".tmp"
            Path(tmp).write_text(json.dumps(self._data, indent=2), encoding="utf-8")
            os.replace(tmp, self._file)
            self._dirty = False
        except Exception as e:
            log.warning(f"Failed to save scrape progress: {e}")

    def flush(self):
        """Save to disk if there are pending changes."""
        if self._dirty:
            self._save()

    def get_offset(self, source: str) -> int:
        return self._data.get(source, {}).get("offset", 0)

    def set_offset(self, source: str, offset: int):
        if source not in self._data:
            self._data[source] = {}
        self._data[source]["offset"] = offset
        self._dirty = True

    def is_done(self, source: str, file_id: str) -> bool:
        return file_id in self._done_sets.get(source, set())

    def mark_done(self, source: str, file_id: str):
        if source not in self._data:
            self._data[source] = {}
        if "done" not in self._data[source]:
            self._data[source]["done"] = []
        if source not in self._done_sets:
            self._done_sets[source] = set()
        if file_id not in self._done_sets[source]:
            self._data[source]["done"].append(file_id)
            self._done_sets[source].add(file_id)
            self._dirty = True
        # Trim if extremely large (500K+ per source = ~25MB JSON per source)
        if len(self._data[source]["done"]) > 500000:
            self._data[source]["done"] = self._data[source]["done"][-400000:]
            self._done_sets[source] = set(self._data[source]["done"])
            log.info(f"[{source}] Trimmed progress from 500K to 400K entries")

    @property
    def total_downloaded(self) -> int:
        return sum(len(v.get("done", [])) for v in self._data.values())


# ── Scraper Orchestrator ──────────────────────────────────────────────────────

class ModScrapeRunner:
    """Coordinates multi-source scraping with round-robin and batch scanning."""

    def __init__(self, mods_dir: Path, progress_file: Path,
                 cf_api_key: str = "", nx_api_key: str = "",
                 batch_size: int = 20):
        self.mods_dir = mods_dir
        self.batch_size = batch_size
        self.progress = ScrapeProgress(progress_file)
        self.cf_api_key = cf_api_key
        self.nx_api_key = nx_api_key
        self.stopped = False
        self.stats = {"downloaded": 0, "skipped": 0, "oversize": 0, "errors": 0, "scanned": 0}

    def stop(self):
        self.stopped = True

    async def collect_batch(self, session: aiohttp.ClientSession) -> list[tuple[Path, str, str]]:
        """Collect a batch of JARs round-robin from all sources.
        Keeps collecting until batch_size is reached or all sources exhausted.
        Returns list of (local_path, mod_name, source) tuples."""
        scrapers = [
            ModrinthScraper(session),
            HangarScraper(session),
            PlanetMinecraftScraper(session),
            CurseForgeScraper(session, self.cf_api_key),  # Works with or without API key
        ]

        batch = []
        exhausted = set()  # Sources that have no more mods

        # Keep doing rounds until we hit batch_size or all sources are exhausted
        while len(batch) < self.batch_size and not self.stopped:
            remaining = self.batch_size - len(batch)
            active_scrapers = [s for s in scrapers if s.name not in exhausted]
            if not active_scrapers:
                break

            per_source = max(1, remaining // len(active_scrapers))

            collected_this_round = 0
            for scraper in active_scrapers:
                if self.stopped or len(batch) >= self.batch_size:
                    break
                if scraper.name in exhausted:
                    continue

                target = min(per_source, self.batch_size - len(batch))
                collected_this_source = 0
                source = scraper.name
                src_dir = self.mods_dir / source
                src_dir.mkdir(parents=True, exist_ok=True)

                offset = self.progress.get_offset(source)
                mod_count = 0
                found_any_mods = False

                try:
                    async for mod in scraper.iter_mods(offset=offset):
                        if self.stopped or collected_this_source >= target:
                            break

                        found_any_mods = True
                        mod_count += 1

                        try:
                            files = await scraper.get_files(mod)
                        except Exception as e:
                            log.warning(f"[{source}] Files error {mod.name}: {e}")
                            self.stats["errors"] += 1
                            continue

                        jar_files = [f for f in files if f.filename.endswith(".jar")]
                        if not jar_files:
                            continue

                        # Download ALL versions of this mod
                        for fi in jar_files:
                            if self.stopped or collected_this_source >= target:
                                break

                            if self.progress.is_done(source, fi.file_id):
                                self.stats["skipped"] += 1
                                continue

                            if fi.size and fi.size > MAX_FILE_SIZE:
                                self.progress.mark_done(source, fi.file_id)
                                self.stats["oversize"] += 1
                                continue

                            safe_slug = self._safe_name(mod.slug or mod.name or mod.source_id)
                            safe_fn = self._safe_name(fi.filename)
                            dest = src_dir / safe_slug / safe_fn
                            dest.parent.mkdir(parents=True, exist_ok=True)

                            if dest.exists():
                                self.progress.mark_done(source, fi.file_id)
                                self.stats["skipped"] += 1
                                continue

                            ok = await scraper.download(fi, dest)

                            if ok and dest.exists():
                                self.progress.mark_done(source, fi.file_id)
                                self.stats["downloaded"] += 1
                                batch.append((dest, mod.name, source))
                                collected_this_source += 1
                                collected_this_round += 1
                                log.info(f"[{source}] Downloaded: {mod.name} / {fi.filename}")
                            elif not ok:
                                self.progress.mark_done(source, fi.file_id)
                                if fi.size and fi.size > MAX_FILE_SIZE:
                                    self.stats["oversize"] += 1
                                else:
                                    self.stats["errors"] += 1

                    self.progress.set_offset(source, offset + mod_count)

                    if not found_any_mods:
                        exhausted.add(source)
                        log.info(f"[{source}] Source exhausted (no more mods)")

                except Exception as e:
                    log.exception(f"[{source}] Source error: {e}")
                    exhausted.add(source)

            # If no progress this round, stop to avoid infinite loop
            if collected_this_round == 0:
                break

        return batch

    @staticmethod
    def _safe_name(name: str) -> str:
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
        return safe[:200] or "unknown"
