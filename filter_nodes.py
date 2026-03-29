#读取cache分析
import re
import os

def parse_size(size_str):
    """
    转换流量为字节，支持 P, T, G, M, K, B
    例如: 953.7P, 100G, 1.5T
    """
    # 增加对 P 和 T 的支持
    units = {
        "B": 1, 
        "K": 1024, 
        "M": 1024**2, 
        "G": 1024**3, 
        "T": 1024**4, 
        "P": 1024**5
    }
    # 匹配数字和单位部分
    match = re.search(r"(\d+(?:\.\d+)?)\s*([BKMGT P])", size_str.upper())
    if match:
        val, unit = match.groups()
        # 去掉单位中的空格
        unit = unit.strip()
        return float(val) * units.get(unit, 1)
    return 0

def is_time_valid(time_str):
    """
    时间判断逻辑：
    1. 包含 '-' (如 -1 day) -> 丢弃（已过期）
    2. 包含 '永不过期' -> 保留
    3. 包含 '天' 或 'day' -> 保留
    4. 小时数 >= 23 -> 保留
    """
    time_str = time_str.lower()
    if "-" in time_str:
        return False
    if "永不过期" in time_str:
        return True
    if any(unit in time_str for unit in ["天", "day"]):
        return True
    hms_match = re.search(r"(\d+):(\d+):(\d+)", time_str)
    if hms_match:
        hours = int(hms_match.group(1))
        if hours >= 23:
            return True
    return False

def filter_cache():
    cache_file = "trial.cache"
    if not os.path.exists(cache_file):
        return

    node_file = "filter_nodes.txt"
    sub_file = "filter_subs.txt"

    with open(cache_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # 极速切分块
    blocks = re.split(r'\n(?=\[http)', content)
    
    nodes_res = []
    subs_res = []

    for block in blocks:
        if "sub_info" not in block or "sub_url" not in block:
            continue
            
        url_title = re.search(r"^\[(http.*?)\]", block, re.MULTILINE)
        # 正则优化：支持提取 G, T, P 等各种单位及其后的时间说明
        info_match = re.search(r"剩余\s+([\d\.]+[BKMGT P]+)(.*?)\)", block, re.IGNORECASE)
        sub_url_match = re.search(r"sub_url\s+(http\S+)", block)

        if url_title and info_match and sub_url_match:
            remain_quota_str = info_match.group(1).strip()
            remain_time_part = info_match.group(2).strip()
            
            # 流量换算为字节进行比较
            quota_bytes = parse_size(remain_quota_str)
            
            # 时间逻辑：如果没有时间说明则视为有效，如果有则进入校验
            time_ok = True if not remain_time_part else is_time_valid(remain_time_part)
            
            # 筛选：流量 > 1G (1024^3 字节) 且 时间有效
            if quota_bytes > (1024**3) and time_ok:
                nodes_res.append(url_title.group(1)) # 保存不带 [] 的网址
                subs_res.append(sub_url_match.group(1)) # 保存订阅链接

    if nodes_res:
        with open(node_file, "w", encoding="utf-8") as f:
            f.write("\n".join(nodes_res))
        with open(sub_file, "w", encoding="utf-8") as f:
            f.write("\n".join(subs_res))

if __name__ == "__main__":
    filter_cache()
