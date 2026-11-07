#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ip-reanchor — Google「送中」拉回工具（从 IP-Sentinel 的 mod_google 拆出并重写）

机制（和 IP-Sentinel 的 Google 模块一致）：
  一个 IP 被 Google 判到中国，多半是被长期流量喂出来的行为画像。
  本工具反着喂：以目标城市的语言、坐标、当天热搜词，用这个 IP 持续发出
  「本地居民在用 Google」的请求（搜索 / 新闻 / 地图 / 平台探针），
  并用持久 Cookie 保持身份连续，让画像慢慢往目标地区漂。

与原版的差别（针对原版三个硬伤做的修正）：
  1. 传输层用 curl_cffi 的 impersonate：TLS(JA3/JA4) 与 HTTP/2 指纹跟真浏览器
     对齐，且 UA 与指纹目标严格同版本，不再出现 curl 指纹配 Chrome UA 的穿帮。
  2. 人设按真实居民构成配比（桌面 Chrome 为主），不再是 1/3 Linux Firefox。
  3. 只保留 Google 纠偏这一条线：没有 Telegram 中枢、没有 OTA 远程执行、
     没有「信用净化」那种证据链最弱的模块。单机、cron 跑、日志可查。

用法：
  python3 reanchor.py regions                     # 列出可选区域
  python3 reanchor.py probe   --region JP-Tokyo   # 只做三核自检，看当前判定
  python3 reanchor.py run     --region JP-Tokyo   # 跑一轮养护 + 自检
  python3 reanchor.py run     --region JP-Tokyo --dry-run   # 只打印计划
  python3 reanchor.py fingerprint                 # 自查出口 IP + TLS 指纹

  也可以不用城市、直接给经纬度（语言/国家没给时自动借最近城市的）：
  python3 reanchor.py run --lat 35.6812 --lon 139.7671
  python3 reanchor.py run --lat 47.6062 --lon -122.3321 --gl US --hl en-US

  双栈机器要指定养哪个地址：--ip-version 4 / --ip-version 6（或 --ipv4 / --ipv6），
  探针、养护动作、词库抓取、出口 IP 检测全程同一协议族，不给则跟随系统默认。
"""

import argparse
import hashlib
import json
import os
import random
import re
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STATE_DIR = Path(os.environ.get("REANCHOR_HOME", Path.home() / ".ip-reanchor"))
TIMEOUT = 15

# --------------------------------------------------------------------------
# 传输层：优先 curl_cffi（浏览器指纹），缺失时降级 urllib 并明确警告
# --------------------------------------------------------------------------
try:
    from curl_cffi import requests as cffi_requests
    from curl_cffi.const import CurlOpt, CurlIpResolve
    HAVE_CFFI = True
except ImportError:
    HAVE_CFFI = False


def _ipresolve(ip_version):
    """--ip-version 4/6 → libcurl 的 IPRESOLVE（等同 curl -4 / -6）。"""
    if ip_version == "4":
        return {CurlOpt.IPRESOLVE: CurlIpResolve.V4}
    if ip_version == "6":
        return {CurlOpt.IPRESOLVE: CurlIpResolve.V6}
    return None


class Transport:
    """按 impersonate 目标发请求；cookies 用普通 dict 由上层持久化。"""

    def __init__(self, impersonate: str, interface: str | None = None,
                 ip_version: str | None = None):
        self.impersonate = impersonate
        self.interface = interface
        self.ip_version = ip_version

    def get(self, url, headers=None, cookies=None, allow_redirects=True):
        headers = headers or {}
        if HAVE_CFFI:
            kw = dict(headers=headers, cookies=cookies or {},
                      allow_redirects=allow_redirects, timeout=TIMEOUT,
                      impersonate=self.impersonate)
            if self.interface:
                kw["interface"] = self.interface
            opts = _ipresolve(self.ip_version)
            if opts:
                kw["curl_options"] = opts
            r = cffi_requests.get(url, **kw)
            new_cookies = {}
            try:
                new_cookies = r.cookies.get_dict()
            except Exception:
                pass
            return r.status_code, dict(r.headers), r.text, new_cookies
        # 降级路径：指纹对不齐，只保证功能
        req = urllib.request.Request(url, headers=headers)
        if cookies:
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))
        opener = urllib.request.build_opener(NoRedirect() if not allow_redirects else urllib.request.HTTPRedirectHandler())
        try:
            with opener.open(req, timeout=TIMEOUT) as resp:
                return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace"), {}
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace") if e.fp else ""
            return e.code, dict(e.headers or {}), body, {}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# --------------------------------------------------------------------------
# 人设：UA 与 impersonate 目标同版本绑定；配比贴近真实居民（桌面 Chrome 为主）
# platform 决定行为矩阵与平台探针
# --------------------------------------------------------------------------
PERSONAS = [
    # (权重, 名称, impersonate, UA, platform)
    (34, "win-chrome", "chrome142",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
     "windows"),
    (22, "mac-chrome", "chrome142",
     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
     "macos"),
    (18, "android-chrome", "chrome131_android",
     "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.104 Mobile Safari/537.36",
     "android"),
    (10, "iphone-safari", "safari184_ios",
     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1",
     "ios"),
    (10, "win-firefox", "firefox133",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
     "windows"),
    (6, "mac-safari", "safari184",
     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
     "macos"),
]


def persona_pool_for_ip(ip: str):
    """哈希锚定：同一个 IP 固定映射到 3 台「家庭设备」，与原版同思路。
    按 md5(ip+人设名) 排序取前 3，保证不撞车、且换 IP 就换一套设备。"""
    ranked = sorted(PERSONAS,
                    key=lambda p: hashlib.md5(f"{ip}|{p[1]}".encode()).hexdigest())
    return ranked[:3]


def pick_persona(pool):
    weights = [p[0] for p in pool]
    return random.choices(pool, weights=weights, k=1)[0]


# --------------------------------------------------------------------------
# 区域与词库
# --------------------------------------------------------------------------
def load_regions():
    data = json.loads((BASE_DIR / "regions.json").read_text(encoding="utf-8"))
    return {r["code"]: r for r in data["regions"]}


def build_custom_region(lat, lon, gl, hl, regions):
    """经纬度自定义区域：--gl/--hl 没给时，借地理上最近的内置城市的国家与语言。"""
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise ValueError(f"经纬度超出范围: lat={lat}, lon={lon}")
    nearest = min(regions.values(),
                  key=lambda r: (r["lat"] - lat) ** 2 + (r["lon"] - lon) ** 2)
    borrowed = gl is None or hl is None
    gl = (gl or nearest["gl"]).upper()
    hl = hl or nearest["hl"]
    # 种子词库按 IP-Sentinel 的国家码存（英国是 UK），热搜 geo 用 GB，统一在这里对齐
    country = "UK" if gl == "GB" else gl
    name = f"自定义坐标 {lat},{lon}" + (f"（国家/语言借 {nearest['code']}）" if borrowed else "")
    return {"code": f"CUSTOM-{lat:.4f},{lon:.4f}", "country": country, "city": "Custom",
            "name": name, "lat": lat, "lon": lon, "hl": hl, "gl": gl}


def accept_language(region):
    hl = region["hl"]
    base = hl.split("-")[0]
    if "-" in hl:
        return f"{hl},{base};q=0.9,en-US;q=0.6,en;q=0.5"
    return f"{hl}-{region['gl']},{hl};q=0.9,en-US;q=0.6,en;q=0.5"


def geo_code(region):
    return "GB" if region["gl"] == "UK" else region["gl"]


def fetch_trending(region, ip_version=None, interface=None):
    """当天热搜：Google Trends RSS（与原版兵工厂同一数据源）。
    也走 impersonate 传输并跟随 --ip-version，免得词库请求从另一条协议栈漏出去。"""
    url = f"https://trends.google.com/trending/rss?geo={geo_code(region)}"
    try:
        if HAVE_CFFI:
            t = Transport("chrome142", interface, ip_version)
            _, _, text, _ = t.get(url, headers={"User-Agent": PERSONAS[0][3]})
            root = ET.fromstring(text.encode())
        else:
            req = urllib.request.Request(url, headers={"User-Agent": PERSONAS[0][3]})
            with urllib.request.urlopen(req, timeout=10) as resp:
                root = ET.fromstring(resp.read())
        words = [it.find("title").text.strip() for it in root.findall("./channel/item")
                 if it.find("title") is not None and it.find("title").text]
        return words
    except Exception:
        return []


def load_keywords(region, log, ip_version=None, interface=None):
    """词库优先级：24h 内的实时热搜缓存 > 仓库种子词库 > 实时现拉。"""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    cache = STATE_DIR / f"kw_{region['country']}.json"
    if cache.exists() and time.time() - cache.stat().st_mtime < 24 * 3600:
        words = json.loads(cache.read_text(encoding="utf-8"))
        if words:
            return words, "cache"
    words = fetch_trending(region, ip_version, interface)
    if words:
        seed = []
        seed_file = BASE_DIR / "seed_keywords" / f"kw_{region['country']}.txt"
        if seed_file.exists():
            seed = [l.strip() for l in seed_file.read_text(encoding="utf-8").splitlines() if l.strip()]
        merged = words + [w for w in seed if w not in words]
        cache.write_text(json.dumps(merged[:100], ensure_ascii=False), encoding="utf-8")
        return merged[:100], "trends-live"
    seed_file = BASE_DIR / "seed_keywords" / f"kw_{region['country']}.txt"
    if seed_file.exists():
        return [l.strip() for l in seed_file.read_text(encoding="utf-8").splitlines() if l.strip()], "seed"
    log("ERROR", "词库为空（热搜拉取失败且无种子词库）")
    return [], "none"


# --------------------------------------------------------------------------
# 日志与状态
# --------------------------------------------------------------------------
def make_logger(region_code):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    log_file = STATE_DIR / "reanchor.log"

    def log(level, msg):
        line = f"[{datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC] [{level:<5}] [{region_code}] {msg}"
        try:
            print(line, flush=True)
        except BrokenPipeError:
            pass
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    return log


def public_ip(interface=None, ip_version=None):
    try:
        if HAVE_CFFI:
            kw = dict(timeout=8, impersonate="chrome")
            if interface:
                kw["interface"] = interface
            opts = _ipresolve(ip_version)
            if opts:
                kw["curl_options"] = opts
            return cffi_requests.get("https://api.ip.sb/ip", **kw).text.strip()
        req = urllib.request.Request("https://api.ip.sb/ip")
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.read().decode().strip()
    except Exception:
        return "unknown"


def jitter_coord(base, range_units):
    """range_units 以 1/10000 度为单位（270 ≈ ±3km，1 ≈ ±11m），与原版一致。"""
    offset = random.randint(-range_units, range_units) / 10000.0
    return round(base + offset, 6)


# --------------------------------------------------------------------------
# 三核自检（与原版同一套判据：跳转 / YT Premium / YT Music）
# --------------------------------------------------------------------------
YT_GL_RE = re.compile(r'"(?:contentRegion|countryCode|INNERTUBE_CONTEXT_GL|GL)":"([A-Za-z]{2})"')
DOMAIN_GL = {"com": "US", "com.hk": "HK", "com.tw": "TW", "co.jp": "JP", "co.uk": "GB",
             "co.kr": "KR", "co.in": "IN", "co.id": "ID", "co.th": "TH", "com.sg": "SG",
             "com.my": "MY", "com.au": "AU", "com.br": "BR", "com.mx": "MX",
             "com.ar": "AR", "co.za": "ZA", "cn": "CN"}


def probe_jump(t: Transport):
    _, headers, _, _ = t.get("http://www.google.com/", allow_redirects=False)
    loc = headers.get("location") or headers.get("Location") or ""
    if not loc:
        return "US"
    if ".google.cn" in loc or "gl=CN" in loc:
        return "CN"
    m = re.search(r"gl=([A-Za-z]{2})", loc)
    if m:
        return m.group(1).upper()
    m = re.search(r"google\.([a-z.]+)", loc)
    if m:
        dom = m.group(1).rstrip(".")
        if dom in DOMAIN_GL:
            return DOMAIN_GL[dom]
        tail = dom.split(".")[-1].upper()
        return tail if len(tail) == 2 else "US"
    return ""


def probe_yt(t: Transport, url):
    _, _, text, _ = t.get(url)
    if "www.google.cn" in text:
        return "CN"
    m = YT_GL_RE.search(text)
    return m.group(1).upper() if m else ""


def run_probe(region, interface, log, ip_version=None):
    # 探针用干净的现代 Chrome 人设裸跑，不带养护 Cookie（原版 v4.2.3 的修正）
    t = Transport("chrome142", interface, ip_version)
    jump = probe_jump(t)
    prem = probe_yt(t, "https://www.youtube.com/premium")
    music = probe_yt(t, "https://music.youtube.com/")
    target = geo_code(region)
    vals = [v for v in (jump, prem, music) if v]
    if not vals:
        verdict = "PROBE_FAIL（三核全灭，可能被风控拦）"
    elif "CN" in vals:
        verdict = "CN_LOCKED（已被判到中国，送中）"
    elif prem == target or music == target:
        verdict = f"OK（目标 {target} 达成；Jump={jump or '无'} Prem={prem or '无'} Music={music or '无'}）"
    else:
        verdict = f"DRIFT（目标 {target}，实际 Jump={jump or '无'} Prem={prem or '无'} Music={music or '无'}）"
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "region": region["code"],
           "ip_version": ip_version or "any",
           "jump": jump, "yt_premium": prem, "yt_music": music, "verdict": verdict}
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with open(STATE_DIR / "probe_history.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    log("PROBE", verdict)
    return rec


# --------------------------------------------------------------------------
# 养护会话（原版 mod_google 的动作轮盘，换成 curl_cffi 传输）
# --------------------------------------------------------------------------
PLATFORM_PROBES = {
    "android": "https://connectivitycheck.gstatic.com/generate_204",
    "ios": "https://captive.apple.com/hotspot-detect.html",
    "macos": "https://captive.apple.com/hotspot-detect.html",
    "windows": "https://www.msftconnecttest.com/connecttest.txt",
    "linux": "https://connectivitycheck.gstatic.com/generate_204",
}
ECO_URLS = ["https://about.google/", "https://safety.google/",
            "https://support.google.com/?hl={hl}"]


def build_action(persona_platform, region, kw, lat, lon, lang_qs):
    dice = random.randint(0, 99)
    q = urllib.parse.quote_plus(kw)
    if persona_platform in ("android", "ios", "macos"):
        cuts = [(25, "search"), (55, "news"), (85, "maps"), (100, "netprobe")]
    else:
        cuts = [(25, "search"), (60, "news"), (80, "eco"), (100, "maps")]
    kind = next(k for cut, k in cuts if dice < cut)
    if kind == "search":
        return kind, f"https://www.google.com/search?q={q}&{lang_qs}"
    if kind == "news":
        return kind, f"https://news.google.com/home?{lang_qs}"
    if kind == "maps":
        return kind, f"https://www.google.com/maps/search/{q}/@{lat},{lon},17z?{lang_qs}"
    if kind == "eco":
        return kind, random.choice(ECO_URLS).format(hl=region["hl"])
    return kind, PLATFORM_PROBES[persona_platform]


def run_session(region, args, log):
    ipv = getattr(args, "ip_version", None)
    if args.bind and ipv:
        bind_is_v6 = ":" in args.bind
        if (ipv == "6") != bind_is_v6:
            log("WARN", f"--bind 的地址族与 --ip-version {ipv} 不一致，以 --bind 为准时请核对")
    ip = public_ip(args.bind, ipv)
    if ip == "unknown":
        log("WARN", "拿不到出口 IP，人设锚定退化为随机")
    pool = persona_pool_for_ip(ip)
    _, pname, impersonate, ua, platform = pick_persona(pool)
    fam = f"IPv{ipv}" if ipv else "跟随系统（未指定 v4/v6）"
    log("INFO", f"出口 IP: {ip} | 协议族: {fam} | 人设: {pname}（池内 {len(pool)} 台固定设备）| 指纹: {impersonate}")
    if not HAVE_CFFI:
        log("WARN", "未装 curl_cffi，当前是降级传输，指纹与 UA 对不齐，--ip-version 也不会生效。先 uv sync")

    keywords, src = load_keywords(region, log, ipv, args.bind)
    if not keywords:
        return False
    log("INFO", f"词库: {len(keywords)} 条（来源 {src}）")

    home_lat = jitter_coord(region["lat"], 270)
    home_lon = jitter_coord(region["lon"], 270)
    log("INFO", f"虚拟住址: {home_lat}, {home_lon}（{region['name']} 基准 ±3km）")

    lang_qs = f"hl={urllib.parse.quote(region['hl'])}&gl={region['gl']}"
    cookie_file = STATE_DIR / f"cookies_{hashlib.md5(ip.encode()).hexdigest()[:10]}.json"
    cookies = {}
    if cookie_file.exists():
        try:
            cookies = json.loads(cookie_file.read_text(encoding="utf-8"))
        except Exception:
            cookies = {}

    total = args.actions if args.actions else random.randint(5, 8)
    headers_base = {"User-Agent": ua, "Accept-Language": accept_language(region)}
    referers = {}
    t = Transport(impersonate, args.bind, ipv)

    for i in range(1, total + 1):
        kw = random.choice(keywords)
        lat = jitter_coord(home_lat, 1)
        lon = jitter_coord(home_lon, 1)
        kind, url = build_action(platform, region, kw, lat, lon, lang_qs)
        headers = dict(headers_base)
        if kind in referers and random.random() < 0.7:
            headers["Referer"] = referers[kind]
        if args.dry_run:
            log("DRY", f"动作[{i}/{total}] {kind:<8} {url[:110]}")
            continue
        try:
            code, _, _, new_cookies = t.get(url, headers=headers, cookies=cookies)
            cookies.update({k: v for k, v in new_cookies.items() if v})
            if 200 <= code < 400:
                referers[kind] = url
            log("EXEC", f"动作[{i}/{total}] {kind:<8} HTTP {code} | {kw[:24]} | {lat},{lon}")
        except Exception as e:
            log("WARN", f"动作[{i}/{total}] {kind} 失败: {type(e).__name__}: {e}")
        if i < total:
            wait = random.randint(1, 3) if args.fast else random.randint(45, 75)
            log("WAIT", f"模拟阅读停留 {wait}s")
            time.sleep(wait)

    if not args.dry_run:
        cookie_file.write_text(json.dumps(cookies, ensure_ascii=False), encoding="utf-8")
        log("INFO", f"Cookie 已存回（{len(cookies)} 条），身份连续性保留")
    return True


def main():
    ap = argparse.ArgumentParser(description="Google 送中拉回（IP-Sentinel Google 模块的独立重写版）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("regions")

    def add_ip_version(p):
        p.add_argument("--ip-version", choices=["4", "6"], default=None,
                       help="强制出口协议族：4 只用 IPv4、6 只用 IPv6（等同 curl -4/-6）；不给则跟随系统")
        # 注意：不能用 -4/-6 短旗，会让 argparse 把 --lon -121.9 的负数经度当成选项
        p.add_argument("--ipv4", dest="ip_version", action="store_const", const="4",
                       help="同 --ip-version 4")
        p.add_argument("--ipv6", dest="ip_version", action="store_const", const="6",
                       help="同 --ip-version 6")

    fp = sub.add_parser("fingerprint")
    add_ip_version(fp)
    for name in ("probe", "run"):
        p = sub.add_parser(name)
        add_ip_version(p)
        p.add_argument("--region", default=None, help="如 JP-Tokyo（先用 regions 查）；与 --lat/--lon 二选一")
        p.add_argument("--lat", type=float, default=None, help="自定义纬度，如 35.6812（须与 --lon 成对）")
        p.add_argument("--lon", type=float, default=None, help="自定义经度，如 139.7671（须与 --lat 成对）")
        p.add_argument("--gl", default=None, help="自定义坐标的目标国家码，如 JP/US/GB（默认借最近城市的）")
        p.add_argument("--hl", default=None, help="自定义坐标的语言，如 ja/en-US（默认借最近城市的）")
        p.add_argument("--bind", default=None, help="绑定出口 IP 或网卡名（多 IP 机器用）")
        if name == "run":
            p.add_argument("--actions", type=int, default=0, help="本轮动作数，默认随机 5-8")
            p.add_argument("--dry-run", action="store_true")
            p.add_argument("--fast", action="store_true", help="测试用：停留缩到 1-3 秒")
            p.add_argument("--no-probe", action="store_true", help="跑完不做三核自检")
    args = ap.parse_args()

    regions = load_regions()
    if args.cmd == "regions":
        for r in regions.values():
            print(f"{r['code']:<28} {r['name']:<34} {r['lat']},{r['lon']}  hl={r['hl']} gl={r['gl']}")
        return
    if args.cmd == "fingerprint":
        ip = public_ip(None, args.ip_version)
        fam = f"（强制 IPv{args.ip_version}）" if args.ip_version else ""
        print(f"出口 IP: {ip}{fam}")
        if HAVE_CFFI:
            for target in ("chrome142", "firefox133", "safari184_ios"):
                try:
                    kw = dict(impersonate=target, timeout=12)
                    opts = _ipresolve(args.ip_version)
                    if opts:
                        kw["curl_options"] = opts
                    r = cffi_requests.get("https://tls.browserleaks.com/json", **kw)
                    d = json.loads(r.text)
                    print(f"{target:<16} UA={d.get('user_agent')[:70]}...")
                    print(f"{'':<16} JA4={d.get('ja4')}  JA3={d.get('ja3_hash')}")
                except Exception as e:
                    print(f"{target}: 失败 {e}")
        else:
            print("未装 curl_cffi，无法做指纹自查")
        return

    if (args.lat is None) != (args.lon is None):
        print("--lat 和 --lon 必须成对给")
        sys.exit(2)
    if args.lat is not None:
        try:
            region = build_custom_region(args.lat, args.lon, args.gl, args.hl, regions)
        except ValueError as e:
            print(str(e))
            sys.exit(2)
    elif args.region:
        region = regions.get(args.region)
        if not region:
            print(f"未知区域 {args.region}，先跑: python3 reanchor.py regions")
            sys.exit(2)
    else:
        print("必须给 --region 或 --lat/--lon 其中一组")
        sys.exit(2)
    log = make_logger(region["code"])
    # 后台由 cron 唤醒时先随机错峰（原版的 jitter 防惊群），终端手动跑不睡
    if args.cmd == "run" and not sys.stdout.isatty() and not args.fast and not args.dry_run:
        jitter = random.randint(0, 180)
        log("INFO", f"后台唤醒，随机错峰休眠 {jitter}s")
        time.sleep(jitter)
    if args.cmd == "probe":
        run_probe(region, args.bind, log, args.ip_version)
    else:
        if run_session(region, args, log) and not args.no_probe and not args.dry_run:
            run_probe(region, args.bind, log, args.ip_version)


if __name__ == "__main__":
    main()
