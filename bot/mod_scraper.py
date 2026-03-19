"""
Mod Scraper — Downloads Minecraft mod JARs from multiple sources.
Integrated with RATScanner for automatic batch scanning.

Sources: Modrinth, CurseForge, PlanetMinecraft, NexusMods, Hangar
Sort: Most downloaded first (where API supports it)
"""
import asyncio
import aiohttp
import json
import logging
import os
import re
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import AsyncGenerator, Optional

try:
    from bs4 import BeautifulSoup
    BS4_OK = True
except ImportError:
    BS4_OK = False

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
                        wait = int(r.headers.get("Retry-After", 30))
                        log.warning(f"[{self.name}] 429, waiting {wait}s")
                        await asyncio.sleep(wait)
                        continue
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
                        await asyncio.sleep(int(r.headers.get("Retry-After", 30)))
                        continue
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
        await self._wait()
        dest.parent.mkdir(parents=True, exist_ok=True)
        for attempt in range(RETRY_COUNT):
            try:
                async with self.session.get(file_info.url,
                        timeout=aiohttp.ClientTimeout(total=DOWNLOAD_TIMEOUT * 2)) as r:
                    if r.status != 200:
                        if r.status == 429:
                            await asyncio.sleep(int(r.headers.get("Retry-After", 30)))
                            continue
                        if attempt < RETRY_COUNT - 1:
                            await asyncio.sleep(RETRY_DELAY * (attempt + 1))
                        continue
                    cl = r.headers.get("Content-Length")
                    if cl and int(cl) > MAX_FILE_SIZE:
                        return False
                    total = 0
                    with open(dest, "wb") as f:
                        async for chunk in r.content.iter_chunked(8192):
                            total += len(chunk)
                            if total > MAX_FILE_SIZE:
                                f.close()
                                dest.unlink(missing_ok=True)
                                return False
                            f.write(chunk)
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
    def __init__(self, session, api_key=""):
        super().__init__(session, RATE_LIMITS["curseforge"])
        self._api_key = api_key
        self._h = {"Accept": "application/json", "x-api-key": api_key}

    @property
    def name(self):
        return "curseforge"

    async def iter_mods(self, offset=0) -> AsyncGenerator[ModInfo, None]:
        if not self._api_key:
            log.warning("No CurseForge API key, skipping")
            return
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
                break
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

    async def get_files(self, mod: ModInfo) -> list[FileInfo]:
        files = []
        idx = 0
        page_size = 50
        while True:
            data = await self._get_json(
                f"{CF_BASE}/v1/mods/{mod.source_id}/files",
                headers=self._h, params={"pageSize": page_size, "index": idx})
            if not data or not data.get("data"):
                break
            for f in data["data"]:
                url = f.get("downloadUrl")
                if not url or not f["fileName"].endswith(".jar"):
                    continue
                if f.get("isServerPack"):
                    continue
                files.append(FileInfo(
                    source="curseforge", file_id=str(f["id"]),
                    filename=f["fileName"], url=url,
                    size=f.get("fileLength"),
                ))
            total = data.get("pagination", {}).get("totalCount", 0)
            idx += page_size
            if idx >= total:
                break
        return files


# ── PlanetMinecraft ───────────────────────────────────────────────────────────

class PlanetMinecraftScraper(BaseScraper):
    def __init__(self, session):
        super().__init__(session, RATE_LIMITS["planetminecraft"])
        self._h = {"User-Agent": "RATScanner/1.0 (mod-scanning-project)"}

    @property
    def name(self):
        return "planetminecraft"

    async def iter_mods(self, offset=0) -> AsyncGenerator[ModInfo, None]:
        if not BS4_OK:
            log.warning("bs4 not installed, skipping PlanetMinecraft")
            return
        page = max(1, (offset // 25) + 1)
        while True:
            html = await self._get_html(
                f"{PMC}/mods/minecraft-java-edition/?order=order_popularity&p={page}",
                headers=self._h)
            if not html:
                break
            soup = BeautifulSoup(html, "html.parser")
            items = soup.select("div.resource_list div.r-info") or \
                    soup.select("div.browse_list div.r-info") or \
                    soup.select("div.resource-list div.r-info")
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
        html = await self._get_html(url, headers=self._h)
        if not html:
            return files
        soup = BeautifulSoup(html, "html.parser")
        dls = soup.select("a.download-link, a[href*='/download/'], a.res_download")
        for i, dl in enumerate(dls):
            href = dl.get("href", "")
            if not href:
                continue
            furl = urljoin(PMC, href)
            fname = href.split("/")[-1] if "/" in href else f"{mod.slug or mod.source_id}.jar"
            if not fname.endswith(".jar"):
                fname += ".jar"
            files.append(FileInfo(
                source="planetminecraft",
                file_id=f"{mod.source_id}_{i}",
                filename=fname, url=furl,
            ))
        return files


# ── NexusMods ─────────────────────────────────────────────────────────────────

class NexusModsScraper(BaseScraper):
    def __init__(self, session, api_key=""):
        super().__init__(session, RATE_LIMITS["nexusmods"])
        self._api_key = api_key
        self._h = {"accept": "application/json", "apikey": api_key}

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
            dl = await self._get_json(
                f"{NX_BASE}/games/{NX_GAME}/mods/{mod.source_id}/files/{fid}/download_link.json",
                headers=self._h)
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
                for platform, dl in ver.get("downloads", {}).items():
                    fi = dl.get("fileInfo", {})
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

    def _load(self) -> dict:
        if self._file.exists():
            try:
                return json.loads(self._file.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def _save(self):
        try:
            self._file.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        except Exception as e:
            log.warning(f"Failed to save scrape progress: {e}")

    def get_offset(self, source: str) -> int:
        return self._data.get(source, {}).get("offset", 0)

    def set_offset(self, source: str, offset: int):
        if source not in self._data:
            self._data[source] = {}
        self._data[source]["offset"] = offset
        self._save()

    def is_done(self, source: str, file_id: str) -> bool:
        done = set(self._data.get(source, {}).get("done", []))
        return file_id in done

    def mark_done(self, source: str, file_id: str):
        if source not in self._data:
            self._data[source] = {}
        if "done" not in self._data[source]:
            self._data[source]["done"] = []
        self._data[source]["done"].append(file_id)
        # Trim if too large (keep last 50k)
        if len(self._data[source]["done"]) > 60000:
            self._data[source]["done"] = self._data[source]["done"][-50000:]
        self._save()

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
        Returns list of (local_path, mod_name, source) tuples."""
        scrapers = [
            ModrinthScraper(session),
            HangarScraper(session),
            PlanetMinecraftScraper(session),
        ]
        if self.cf_api_key:
            scrapers.append(CurseForgeScraper(session, self.cf_api_key))
        if self.nx_api_key:
            scrapers.append(NexusModsScraper(session, self.nx_api_key))

        if not scrapers:
            return []

        # How many per source this batch
        per_source = max(1, self.batch_size // len(scrapers))
        remainder = self.batch_size - (per_source * len(scrapers))

        batch = []
        sem = asyncio.Semaphore(3)

        for i, scraper in enumerate(scrapers):
            if self.stopped:
                break

            target = per_source + (1 if i < remainder else 0)
            collected_this_source = 0
            source = scraper.name
            src_dir = self.mods_dir / source
            src_dir.mkdir(parents=True, exist_ok=True)

            offset = self.progress.get_offset(source)
            mod_count = 0

            try:
                async for mod in scraper.iter_mods(offset=offset):
                    if self.stopped or collected_this_source >= target:
                        break

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

                    # Just take the first (latest) JAR per mod to keep batches moving
                    fi = jar_files[0]

                    if self.progress.is_done(source, fi.file_id):
                        self.stats["skipped"] += 1
                        continue

                    # Check size
                    if fi.size and fi.size > MAX_FILE_SIZE:
                        self.progress.mark_done(source, fi.file_id)
                        self.stats["oversize"] += 1
                        continue

                    # Build dest path
                    safe_slug = self._safe_name(mod.slug or mod.name or mod.source_id)
                    safe_fn = self._safe_name(fi.filename)
                    dest = src_dir / safe_slug / safe_fn
                    dest.parent.mkdir(parents=True, exist_ok=True)

                    if dest.exists():
                        self.progress.mark_done(source, fi.file_id)
                        self.stats["skipped"] += 1
                        continue

                    # Download
                    async with sem:
                        ok = await scraper.download(fi, dest)

                    if ok and dest.exists():
                        self.progress.mark_done(source, fi.file_id)
                        self.stats["downloaded"] += 1
                        batch.append((dest, mod.name, source))
                        collected_this_source += 1
                        log.info(f"[{source}] Downloaded: {mod.name} / {fi.filename}")
                    elif not ok:
                        self.progress.mark_done(source, fi.file_id)
                        if fi.size and fi.size > MAX_FILE_SIZE:
                            self.stats["oversize"] += 1
                        else:
                            self.stats["errors"] += 1

                self.progress.set_offset(source, offset + mod_count)

            except Exception as e:
                log.exception(f"[{source}] Source error: {e}")

        return batch

    @staticmethod
    def _safe_name(name: str) -> str:
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
        return safe[:200] or "unknown"
