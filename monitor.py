import os
import json
import urllib.request
import sys
import datetime
import time
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE = BASE_DIR / "index_template.html"
OUTPUT = BASE_DIR / "index.html"
BASELINE_FILE = BASE_DIR / "baseline.json"
LOG_DIR = BASE_DIR / "logs"

IPS = ["111.71.0.8", "111.71.212.8", "111.71.213.8", "111.71.214.8", "111.71.215.8", "111.71.64.8"]
# 根據中華電信日誌：2L3BR3 機房的預期正確最後一跳核心骨幹網段
EXPECTED_LAST_HOP_SEGMENT = "210.65.126." 
BR_NAME = "2L3BR3"

LOG_DIR.mkdir(parents=True, exist_ok=True)

def fetch_globalping_traceroute_official(target):
    """
    100% 採用同事的黃金源碼機制：使用 urllib 搭配專屬白名單標頭與正確的雙階段輪詢
    """
    api_url = "https://globalping.io"
    payload = json.dumps({
        "type": "traceroute",
        "target": target,
        "locations": [{"country": "TW"}],
        "limit": 1
    }).encode("utf-8")
    
    req = urllib.request.Request(
        api_url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "GitHub-Network-Probe"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            measurement_id = json.loads(resp.read().decode("utf-8")).get("id")
    except Exception as e:
        return f"發起請求失敗: {e}"
 
    poll_url = f"{api_url}/{measurement_id}"
    for _ in range(15):
        time.sleep(2)
        try:
            # 輪詢時不帶 data 參數，確保 urllib 自動發出 GET 請求，避開 405 封鎖
            req_poll = urllib.request.Request(poll_url, headers={"User-Agent": "GitHub-Network-Probe"})
            with urllib.request.urlopen(req_poll, timeout=15) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                if res_data.get("status") == "finished":
                    results = res_data.get("results", [])
                    if results:
                        # 成功提取陣列第一筆的 rawOutput 路由純文字
                        return results[0].get("result", {}).get("rawOutput", "")
        except Exception:
            pass
    return "探測逾時"

def parse_globalping_mtr(raw_out):
    """
    精準解析真實日誌格式：
    範例：" 5  210-65-126-101.hinet-ip.hinet.net (210.65.126.101)  5.374 ms"
    """
    last_ip = None
    last_hop = 0
    lines = raw_out.splitlines()
    
    # 匹配開頭跳數，並抓取後面包含在小括號內的實體 IP 位址
    ip_in_parentheses_re = re.compile(r"^\s*(\d+)\s+.*?\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)")
    
    for line in lines:
        m = ip_in_parentheses_re.match(line)
        if m:
            hop = int(m.group(1))
            ip = m.group(2)
            last_hop = hop
            last_ip = ip
            
    return last_hop, last_ip

def load_baseline():
    if BASELINE_FILE.exists():
        try: return json.loads(BASELINE_FILE.read_text(encoding='utf-8'))
        except: return {}
    return {}

def save_baseline(data):
    BASELINE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')

def build_row_html(ip, net, component, nat_group, baseline, current, br_name=BR_NAME):
    # 檢查抓到的 Last Hop 是否屬於中華電信預期的 210.65.126.x 核心網段
    is_valid_route = current['ip'] and current['ip'].startswith(EXPECTED_LAST_HOP_SEGMENT)

    if baseline is None:
        judgement = ("text-emerald-400", "✓", "基準建立")
        reached_br = ("text-emerald-400", "✓", br_name)
        status_text = "基準已建立"
    else:
        diff = current['hop'] - baseline['hop'] if current['hop'] is not None else 0
        diff_sign = f"{'+' if diff>0 else ''}{diff}"
        
        if is_valid_route:
            reached_br = ("text-emerald-400", "✓", br_name)
            judgement = ("text-emerald-400", "✓", "正常")
            status_text = f"正常抵達 {br_name} ({diff_sign})"
        else:
            reached_br = ("text-rose-400", "✕", "未抵達 BR")
            judgement = ("text-rose-400", "✕", "異常")
            status_text = f"最後回應: {current['ip'] if current['ip'] else '無回應'}"

    ip_cell = f"<div class='text-sm ip-mono text-cyan-300 font-semibold'>{ip}</div><div class='text-xs text-slate-400'>{net}</div>"
    component_cell = f"<div class='text-sm'>{component}</div><div class='text-xs text-slate-400'>{nat_group}</div>"
    
    if baseline is None:
        hop_cell = f"<div class='text-sm font-medium'>{current['hop'] if current['hop'] else '-'}</div><div class='text-xs text-slate-400'>(基準建立)</div>"
    else:
        diff = current['hop'] - baseline['hop'] if current['hop'] is not None else 0
        diff_sign = f"{'+' if diff>0 else ''}{diff}"
        hop_cell = f"<div class='text-sm font-medium'>{current['hop'] if current['hop'] is not None else '-'}</div><div class='text-xs text-slate-400'>(基:{baseline['hop']} / 差:{diff_sign})</div>"
        
    last_node = current['ip'] if current['ip'] else "<span class='text-rose-300'>無回應</span>"
    last_node_cell = f"<div class='text-sm ip-mono text-sky-400 font-medium'>{last_node}</div><div class='text-xs text-slate-400'>最後一跳</div>"
    
    reached_cls, _, reached_label = reached_br if baseline is not None else ("text-emerald-400","✓", br_name)
    reached_cell = f"<div class='inline-flex items-center gap-2 {reached_cls} font-medium'><span>{reached_label}</span></div>"
    
    status_cell = f"<div class='text-sm'>{status_text}</div>"
    judgement_cls, _, judgement_label = judgement if baseline is not None else ("text-emerald-400","✓","基準")
    judgement_cell = f"<div class='inline-flex items-center gap-2 {judgement_cls} font-semibold'><span>{judgement_label}</span></div>"

    log_file = f"logs/{ip}.log"
    view_btn = f"<a class='px-3 py-1 text-sm text-sky-500 bg-sky-900/30 rounded-md hover:bg-sky-800/40 transition' href='{log_file}' target='_blank'>查看</a>"

    return f"""
    <tr class="hover:bg-slate-800/50 transition-transform transform hover:-translate-y-0.5">
      <td class="px-4 py-4">{ip_cell}</td>
      <td class="px-4 py-4">{component_cell}</td>
      <td class="px-4 py-4 text-center">{hop_cell}</td>
      <td class="px-4 py-4">{last_node_cell}</td>
      <td class="px-4 py-4">{reached_cell}</td>
      <td class="px-4 py-4">{status_cell}</td>
      <td class="px-4 py-4 text-center">{judgement_cell}</td>
      <td class="px-4 py-4 text-center">{view_btn}</td>
    </tr>
    """

def main():
    baseline = load_baseline()
    results = {}
    rows = []
    ok_count = 0
    bad_count = 0
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    meta_map = {
        "111.71.0.8": {"net": "111.71.0.0/17 (前半)", "comp": "3L1EPG1", "group": "NAT7/8"},
        "111.71.212.8": {"net": "111.71.212.0/23 (前半)", "comp": "2L3EPG1", "group": "NAT7/8"},
        "111.71.213.8": {"net": "111.71.212.0/23 (後半)", "comp": "2L3EPG1", "group": "NAT7/8"},
        "111.71.214.8": {"net": "111.71.214.0/23 (前半)", "comp": "3L1EPG1", "group": "NAT7/8"},
        "111.71.215.8": {"net": "111.71.214.0/23 (後半)", "comp": "3L1EPG1", "group": "NAT7/8"},
        "111.71.64.8": {"net": "111.71.64.0/24", "comp": "3L1EPG6", "group": "NAT7/8"},
    }

    for ip in IPS:
        print(f"正在執行 Globalping 台灣探針巡檢 IP: {ip} ...")
        tr_out = fetch_globalping_traceroute_official(ip)
        
        log_path = LOG_DIR / f"{ip}.log"
        log_path.write_text(f"=== {now} Globalping (Taiwan Node) to {ip} ===\n\n{tr_out}\n", encoding='utf-8')

        hop, last_ip = parse_globalping_mtr(tr_out)
        current = {"hop": hop, "ip": last_ip, "raw": tr_out, "ts": now}
        bl = baseline.get(ip)
        
        meta = meta_map[ip]
        is_valid_route = current['ip'] and current['ip'].startswith(EXPECTED_LAST_HOP_SEGMENT)
        
        if bl is None:
            if current['hop'] > 0:
                baseline[ip] = {"hop": current['hop'], "ip": current['ip'], "created": now}
                save_baseline(baseline)
            ok_count += 1
            row = build_row_html(ip, meta["net"], meta["comp"], meta["group"], None, current)
        else:
            if is_valid_route:
                ok_count += 1
            else:
                bad_count += 1
            row = build_row_html(ip, meta["net"], meta["comp"], meta["group"], bl, current)
            
        rows.append(row)
        results[ip] = {"baseline": baseline.get(ip), "current": current}

    if not TEMPLATE.exists():
        sys.exit(1)
        
    tpl = TEMPLATE.read_text(encoding='utf-8')
    out_html = tpl.replace("<!-- TABLE_ROWS -->", "\n".join(rows))
    meta_js = f"<script>window.__MONITOR_META__ = {{ last_updated: '{now}', total: {len(IPS)}, ok: {ok_count}, bad: {bad_count} }};</script>\n"
    out_html = out_html.replace("<body", f"{meta_js}<body", 1)

    OUTPUT.write_text(out_html, encoding='utf-8')
    (BASE_DIR / "results.json").write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"巡檢完成。正常: {ok_count}, 異常: {bad_count}")

if __name__ == "__main__":
    main()
