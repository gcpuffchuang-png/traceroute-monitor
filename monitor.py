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

IPS = [
    "2001:B400:E200::1", "2001:B400:E250::1", "2001:B400:E2A0::1", "2001:B400:E260::1", 
    "2001:B400:E300::1", "2001:B400:E350::1", "2001:B400:E3A0::1", "2001:B400:E3E0::1"
]

# 聽從您的要求：使用正規表示法精準支持 156:、157:、158: 核心骨幹網段
EXPECTED_LAST_HOP_PATTERN = r"^2001:b400:15[678]:"
BR_NAME = "CHTM BR"

LOG_DIR.mkdir(parents=True, exist_ok=True)

def fetch_globalping_traceroute_official(target):
    """
    採用同事給的原始黃金網址與 urllib 輪詢機制
    """
    api_url = "https://api.globalping.io/v1/measurements"
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
            req_poll = urllib.request.Request(poll_url, headers={"User-Agent": "GitHub-Network-Probe"})
            with urllib.request.urlopen(req_poll, timeout=15) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                if res_data.get("status") == "finished":
                    results = res_data.get("results", [])
                    if results:
                        return results[0].get("result", {}).get("rawOutput", "")
        except Exception:
            pass
    return "探測逾時"

def parse_globalping_mtr(raw_out):
    """
    智能路由解析器：自動過濾 !N 錯誤封包，由下往上逆向提取有效節點
    """
    lines = raw_out.splitlines()
    ip_in_parentheses_re = re.compile(r"^\s*(\d+)\s+.*?\(([0-9a-fA-F:\.]+)\)")
    
    for line in reversed(lines):
        if "!N" in line or "!H" in line or "!P" in line:
            print(f"[異常過濾] 已剔除錯誤行: {line.strip()}")
            continue
            
        m = ip_in_parentheses_re.match(line)
        if m:
            return int(m.group(1)), m.group(2)
            
    return 0, None

def load_baseline():
    if BASELINE_FILE.exists():
        try: return json.loads(BASELINE_FILE.read_text(encoding='utf-8'))
        except: return {}
    return {}

def save_baseline(data):
    BASELINE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')

def build_row_html(ip, net, component, nat_group, baseline, current, br_name=BR_NAME):
    """
    高端深色科技戰情室風格的 HTML 生成器
    """
    # 進行不分大小寫的 Regex 核心網段匹配驗證
    is_valid = current['ip'] and bool(re.match(EXPECTED_LAST_HOP_PATTERN, current['ip'], re.IGNORECASE))
    
    # 1. 處理【是否抵達 BR】與【綜合判定】標籤樣式 (還原附圖視覺)
    if is_valid:
        reached_br_html = f"""<div class="text-emerald-400 font-medium flex items-center gap-1 text-xs">
            <span>✓ B-{br_name}</span>
        </div>
        <div class="text-[11px] text-slate-400 ip-mono mt-0.5">{current['ip']}</div>"""
        
        judgement_html = """<div class="text-emerald-400 font-medium flex items-center gap-1 text-xs">
            <span>✓ 國內外正常</span>
        </div>"""
    else:
        last_node_ip = current['ip'] if current['ip'] else "無回應"
        reached_br_html = f"""<div class="text-rose-400 font-medium flex items-center gap-1 text-xs">
            <span>✕ 未抵達 BR</span>
        </div>
        <div class="text-[11px] text-rose-300/70 ip-mono mt-0.5">{last_node_ip}</div>"""
        
        judgement_html = """<div class="text-rose-400 font-medium flex items-center gap-1 text-xs">
            <span>✕ 路由異常</span>
        </div>"""

    # 2. 處理【跳數、基準與差值】格式 (如：8 (基:7 / 差:+1))
    if baseline is None:
        hop_html = f"""<div class="text-sm font-medium text-white">{current['hop'] if current['hop'] else '-'}</div>
        <div class="text-[10px] text-slate-500">(新基準建立)</div>"""
        status_text = "正常連通" if is_valid else "未達核心網段"
    else:
        diff = current['hop'] - baseline['hop'] if current['hop'] is not None and baseline.get('hop') is not None else 0
        diff_sign = f"+{diff}" if diff > 0 else f"{diff}"
        hop_html = f"""<div class="text-sm font-medium text-white">{current['hop'] if current['hop'] is not None else '-'}</div>
        <div class="text-[10px] text-slate-400">(基:{baseline['hop']} / 差:{diff_sign})</div>"""
        status_text = f"正常抵達 {br_name}" if is_valid else "路徑偏差/異常"

    # 封裝大氣、具微幅懸停效果的深色表格 Row
    return f"""
    <tr class="hover:bg-slate-800/30 transition border-b border-slate-800/40 text-slate-300">
      <td class="px-6 py-4">
        <div class="text-sm font-semibold text-cyan-300 ip-mono">{ip}</div>
        <div class="text-[11px] text-slate-500 mt-0.5">{net}</div>
      </td>
      <td class="px-6 py-4">
        <div class="text-sm font-medium text-slate-200">{component}</div>
        <div class="text-[11px] text-slate-500 mt-0.5">{nat_group}</div>
      </td>
      <td class="px-6 py-4 text-center">{hop_html}</td>
      <td class="px-6 py-4">
        <div class="text-xs text-sky-400 ip-mono font-medium">{current['ip'] if current['ip'] else '<span class="text-slate-600">* * *</span>'}</div>
      </td>
      <td class="px-6 py-4">{reached_br_html}</td>
      <td class="px-4 py-4">{judgement_html}</td>
      <td class="px-6 py-4 text-center">
        <a class="px-2.5 py-1 text-xs text-cyan-400 bg-cyan-950/40 border border-cyan-800/30 rounded-md hover:bg-cyan-900/60 transition" href="logs/{ip}.log" target="_blank">查看</a>
      </td>
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
        "2001:B400:E200::1": {"net": "IPv6 行網巡檢", "comp": "2L3EPG1", "group": "NAT7/8"},
        "2001:B400:E250::1": {"net": "IPv6 行網巡檢", "comp": "2L3EPG2", "group": "NAT7/8"},
        "2001:B400:E2A0::1": {"net": "IPv6 行網巡檢", "comp": "2L3EPG3", "group": "NAT7/8"},
        "2001:B400:E260::1": {"net": "IPv6 行網巡檢", "comp": "2L3EPG4", "group": "NAT7/8"},
        "2001:B400:E300::1": {"net": "IPv6 行網巡檢", "comp": "3L1EPG1", "group": "NAT7/8"},
        "2001:B400:E350::1": {"net": "IPv6 行網巡檢", "comp": "3L1EPG2", "group": "NAT7/8"},
        "2001:B400:E3A0::1": {"net": "IPv6 行網巡檢", "comp": "3L1EPG3", "group": "NAT7/8"},
        "2001:B400:E3E0::1": {"net": "IPv6 行網巡檢", "comp": "3L1EPG4U", "group": "NAT7/8"},
    }

    for ip in IPS:
        print(f"正在執行 Globalping 台灣探針巡檢 IP: {ip} ...")
        tr_out = fetch_globalping_traceroute_official(ip)
        
        log_path = LOG_DIR / f"{ip}.log"
        log_path.write_text(f"=== {now} Globalping (Taiwan Node) to {ip} ===\n\n{tr_out}\n", encoding='utf-8')

        hop, last_ip = parse_globalping_mtr(tr_out)
        current = {"hop": hop, "ip": last_ip, "raw": tr_out, "ts": now}
        bl = baseline.get(ip)
        
        meta = meta_map.get(ip, {"net": "IPv6 新增網段", "comp": "UNKNOWN", "group": "NAT7/8"})
        is_valid = current['ip'] and bool(re.match(EXPECTED_LAST_HOP_PATTERN, current['ip'], re.IGNORECASE))
        
        if is_valid:
            ok_count += 1
        else:
            bad_count += 1

        if bl is None:
            if is_valid and current['hop'] > 0:
                baseline[ip] = {"hop": current['hop'], "ip": current['ip'], "created": now}
                save_baseline(baseline)
            row = build_row_html(ip, meta["net"], meta["comp"], meta["group"], None, current)
        else:
            row = build_row_html(ip, meta["net"], meta["comp"], meta["group"], bl, current)
            
        rows.append(row)
        results[ip] = {"baseline": baseline.get(ip), "current": current}

    if not TEMPLATE.exists():
        sys.exit(1)
        
    tpl = TEMPLATE.read_text(encoding='utf-8')
    rows_html = "\n".join(rows)
    out_html = tpl.replace("<!-- TABLE_ROWS -->", rows_html)
    
    meta_js = f"<script>window.__MONITOR_META__ = {{ last_updated: '{now}', total: {len(IPS)}, ok: {ok_count}, bad: {bad_count} }};</script>\n"
    out_html = out_html.replace("<body", f"{meta_js}<body", 1)

    OUTPUT.write_text(out_html, encoding='utf-8')
    (BASE_DIR / "results.json").write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"巡檢完成。正常(綠燈): {ok_count}, 異常(紅燈): {bad_count}")

if __name__ == "__main__":
    main()
