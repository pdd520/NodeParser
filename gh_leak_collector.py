import requests
import re
import base64
import yaml
from urllib.parse import urlparse

HEADERS = {"User-Agent": "Mozilla/5.0"}

SUB_SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/adiwzx/freenode/main/sub",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/subscribe.txt",
    "https://raw.githubusercontent.com/learnhard-cn/free_proxy_ss/main/free",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt",
    "https://sub.pmsub.me/clash.yaml",
    "https://sub.pmsub.me/base64",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/freefq/free/master/ssr",
]

KEYWORDS = ["vmess://", "vless://", "trojan://", "ss://", "ssr://"]

def safe_b64decode(data):
    try:
        data += "=" * (-len(data) % 4)
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except:
        return ""

def extract_links(text):
    results = set()

    # 1. 明文节点
    for kw in KEYWORDS:
        for line in text.splitlines():
            if kw in line:
                results.add(line.strip())

    # 2. Base64 订阅
    if re.fullmatch(r"[A-Za-z0-9+/=]+", text.strip()):
        decoded = safe_b64decode(text.strip())
        for kw in KEYWORDS:
            for line in decoded.splitlines():
                if kw in line:
                    results.add(line.strip())

    # 3. Clash YAML
    if "proxies:" in text or "Proxy:" in text:
        try:
            data = yaml.safe_load(text)
            proxies = data.get("proxies", []) or data.get("Proxy", [])
            for p in proxies:
                server = p.get("server")
                port = p.get("port")
                if server and port:
                    results.add(f"{server}:{port}")
        except:
            pass

    return results

def extract_domains(links):
    domains = set()
    for link in links:
        try:
            domain = urlparse(link).netloc
            if domain and "." in domain:
                domains.add(domain)
        except:
            pass
    return domains

def run():
    all_links = set()

    print("🚀 开始从订阅源收集泄露订阅...\n")

    for src in SUB_SOURCES:
        print(f"🔍 正在抓取：{src}")
        try:
            r = requests.get(src, headers=HEADERS, timeout=10)
            if r.status_code == 200:
                all_links |= extract_links(r.text)
        except:
            pass

    domains = extract_domains(all_links)

    print("\n🎉 完成订阅源扫描！")
    print(f"📌 发现节点/订阅：{len(all_links)} 条")
    print(f"📌 提取域名：{len(domains)} 个")

    with open("leaked_nodes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(all_links)))

    with open("leaked_domains.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(domains)))

if __name__ == "__main__":
    run()
