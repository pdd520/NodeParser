import requests
import re
import logging
import csv
import html
import base64
import json
import time
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 基础配置 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 包含以下关键词的订阅链接将被直接跳过，不爬取其节点
BLACKLIST_DOMAINS = [
    'mojie.app',
    'xn--ehqa22b.site',
    'subscribe002.awsy.top',
    'onlysub.mjurl.com',
    'store.mmins.top',
    'rssstarlink.ei38d3if3.xyz',
    'ktm001.top',
    '52pokemon.yunjnet.com',
    'mojie.link'
]

CHANNELS = ['vpn_3000','ccbaohe']

PROTO_PATTERN = r"(?:vmess|vless|trojan|ss|ssr|hysteria|hysteria2|hy2)://[A-Za-z0-9+/=_.:\-?&%@#]+"
SUB_PATTERN = r"https?://[^\s<>\"'；]+?(?:sub|subscribe|api/v\d/|token=|link/|/s/|/clash/|/v2ray/|/free/)[A-Za-z0-9\-\.=&?%/]+"

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'}

def safe_decode(data):
    try:
        data = re.sub(r'\s+', '', data.strip())
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except:
        return ""

def extract_nodes_only(text):
    nodes = re.findall(PROTO_PATTERN, text)
    b64_blocks = re.findall(r"[A-Za-z0-9+/]{80,}", text)
    for block in b64_blocks:
        decoded = safe_decode(block)
        if "://" in decoded:
            nodes.extend(re.findall(PROTO_PATTERN, decoded))
    return [n.split('<')[0].split('"')[0].strip() for n in nodes if n]

# --- 通用流量/到期解析器 ---
def parse_usage_and_expire(text, headers):
    # 1) Header 格式
    header = headers.get('Subscription-Userinfo') or headers.get('subscription-userinfo')
    if header:
        info = {}
        for item in header.split(';'):
            if '=' in item:
                k, v = item.split('=', 1)
                try:
                    info[k.strip().lower()] = int(v.strip())
                except:
                    pass
        if info:
            return info

    # 2) JSON 格式
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            info = {}
            for k in ["upload", "download", "total", "expire", "expiration"]:
                if k in data:
                    try:
                        info[k] = int(data[k])
                    except:
                        pass
            if info:
                return info
    except:
        pass

    # 3) 文本 key=value 格式
    info = {}
    for item in text.replace("\n", ";").split(";"):
        if "=" in item:
            k, v = item.split("=", 1)
            try:
                info[k.strip().lower()] = int(v.strip())
            except:
                pass
    return info

# --- 订阅抓取 ---
def fetch_sub_content(sub_url):
    try:
        r = requests.get(sub_url, headers=HEADERS, timeout=12)
        if r.status_code != 200:
            return [], False

        content = r.text
        if "://" not in content:
            content = safe_decode(content)

        # --- 通用流量/时间判断 ---
        info = parse_usage_and_expire(content, r.headers)

        upload = info.get("upload", 0)
        download = info.get("download", 0)
        total = info.get("total", 0)
        expire = info.get("expire") or info.get("expiration")
        now = int(time.time())

        # 流量用尽
        if total > 0 and (upload + download) >= total:
            return [], False

        # 已过期
        if expire and now >= expire:
            return [], False

        # --- 提取节点 ---
        nodes = extract_nodes_only(content)
        if nodes:
            return nodes, True

    except:
        pass

    return [], False

def process_channel_only_subs(channel):
    try:
        r = requests.get(f"https://t.me/s/{channel}", headers=HEADERS, timeout=15)
        if r.status_code != 200:
            return channel, [], []

        text = html.unescape(r.text)
        sub_only_nodes = []
        valid_subs = []

        raw_subs = re.findall(SUB_PATTERN, text)

        for sub in set(raw_subs):
            clean_sub = sub.rstrip('.,;)')

            if any(domain in clean_sub for domain in BLACKLIST_DOMAINS):
                continue

            nodes_from_sub, is_valid = fetch_sub_content(clean_sub)
            if is_valid:
                sub_only_nodes.extend(nodes_from_sub)
                valid_subs.append(clean_sub)

        return channel, list(set(sub_only_nodes)), valid_subs
    except:
        return channel, [], []

def main():
    all_sub_nodes, all_valid_links, stats = [], [], {}
    logger.info("📡 模式：纯订阅链接节点提取 (域名过滤 + 流量校验 + 到期校验)")

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(process_channel_only_subs, ch): ch for ch in CHANNELS}
        for f in tqdm(as_completed(futures), total=len(CHANNELS), desc="抓取进度"):
            ch, n_list, s_list = f.result()
            stats[ch] = len(n_list)
            all_sub_nodes.extend(n_list)
            all_valid_links.extend(s_list)

    unique_nodes = sorted(list(set(all_sub_nodes)))
    unique_subs = sorted(list(set(all_valid_links)))

    with open("tg_collector.txt", "w", encoding="utf-8") as f:
        f.write(f"# 纯订阅源节点总数: {len(unique_nodes)}\n")
        f.writelines(f"{n}\n" for n in unique_nodes)

    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(unique_nodes).encode()).decode())

    with open("valid_subs.txt", "w", encoding="utf-8") as f:
        f.writelines(f"{s}\n" for s in unique_subs)

    with open("tg_channel_stats.csv", "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["channel", "valid_sub_nodes"])
        for ch, count in stats.items():
            writer.writerow([ch, count])

    logger.info(f"✅ 提取完成！排除黑名单后总节点: {len(unique_nodes)}, 有效订阅数: {len(unique_subs)}")

if __name__ == "__main__":
    main()
