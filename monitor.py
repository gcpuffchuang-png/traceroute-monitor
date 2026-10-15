import os
import json
import re
import sys
import datetime
import time
import requests
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE = BASE_DIR / "index_template.html"
OUTPUT = BASE_DIR / "index.html"
BASELINE_FILE = BASE_DIR / "baseline.json"
LOG_DIR = BASE_DIR / "logs"

IPS = ["111.71.0.8", "111.71.212.8", "111.71.213.8", "111.71.214.8", "111.71.215.8", "111.71.64.8"]
BR_NAME = "2L3BR3"
LOG_DIR.mkdir(parents=True, exist_ok=True)

def fetch_globalping_traceroute(ip):
    """
    呼叫 Globalping API，指定使用台灣(Taiwan)的探針發起真實的 Traceroute。
    已補上 GET 輪詢時的 Headers 偽裝，徹底解決 405 Method Not Allowed 錯誤。
    """
    # 官方標準端點網址 (POST 建立任務)
    api_url = "https://api.globalping.io/v1/measurements"
    
    payload = {
        "type": "traceroute",
        "target": ip,
        "locations": [{"country": "TW"}], # 指定台灣實體探針
        "limit": 1
    }
    
    # 建立標準瀏覽器標頭，穿透 Globalping 的自動化爬蟲防護牆
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    try:
        # 1. 建立測試任務 (POST)
        response = requests.post(api_url, json=payload, headers=headers, timeout=15)
        if response.status_code != 202:
            return f"Globalping 建立任務失敗，狀態碼: {response.status_code}，原因: {response.text[:100]}"
        
        task_id = response.json().get("id")
        result_url = f"https://globalping.io{task_id}"
        
        # 2. 輪詢獲取結果 (GET) —— ✨ 這裡補上 headers=headers 解決 405 關鍵 ✨
        for _ in range(12): # 最多等待 24 秒
            time.sleep(2)
            # 必須帶入相同的瀏覽器標頭，否則會被 Globalping 防火牆判定為非法 HTTP 方法而噴 405
            res = requests.get(result_url, headers=headers, timeout=15)
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "finished":
                    results = data.get("results", [])
                    if results:
                        return results[0].get("result", {}).get("rawOutput", "無輸出結果")
        return "Globalping 測試逾時，台灣探針未能及時回傳路由資料。"
    except Exception as e:
        return f"連線至 Globalping API 失敗: {e}"


def parse_globalping_mtr(raw_out):
    """
    解析 Globalping 輸出的標準 Linux traceroute 格式，提取 Last Hop。
    """
    last_ip = None
    last_hop = 0
    lines = raw_out.splitlines()
    
    # 匹配 " 1  10.0.0.1" 或 "12  210.65.1.1"
    ip_re = re.compile(r"^\s*(\d+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")
    
    for line in lines:
        m = ip_re.match(line)
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
    if baseline is None:
        judgement = ("text-emerald-400", "✓", "基準建立")
        reached_br = ("text-emerald-400", "✓", br_name)
        status_text = "基準已建立"
    else:
        diff = current['hop'] - baseline['hop'] if current['hop'] is not None else 0
        diff_sign = f"{'+' if diff>0 else ''}{diff}"
        if current['ip'] and baseline.get('ip') and (current['ip'] == baseline.get('ip')):
            reached_br = ("text-emerald-400", "✓", br_name)
            judgement = ("text-emerald-400", "✓", "正常")
            status_text = f"正常抵達 {br_name} ({diff_sign})"
        else:
            reached_br = ("text-rose-400", "✕", "未抵達 BR")
            judgement = ("text-rose-400", "✕", "異常")
            status_text = f"最後回應 {current['ip']}" if current['ip'] else "無回應 / 路由中斷"

    ip_cell = f"<div class='text-sm ip-mono text-cyan-300 font-semibold'>{ip}</div><div class='text-xs text-slate-400'>{net}</div>"
    component_cell = f"<div class='text-sm'>{component}</div><div class='text-xs text-slate-400'>{nat_group}</div>"
    
    if baseline is None:
        hop_cell = f"<div class='text-sm font-medium'>{current['hop'] if current['hop'] else '-'}</div><div class='text-xs text-slate-400'>(基準建立)</div>"
    else:
        diff = current['hop'] - baseline['hop'] if current['hop'] is not None else 0
        diff_sign = f"{'+' if diff>0 else ''}{diff}"
        hop_cell = f"<div class='text-sm font-medium'>{current['hop'] if current['hop'] is not None else '-'}</div><div class='text-xs text-slate-400'>(基:{baseline['hop']} / 差:{diff_sign})</div>"
        
    last_node = current['ip'] if current['ip'] else "<span class='text-rose-300'>無回應</span>"
    last_node_cell = f"<div class='text-sm ip-mono text-sky-400 font-medium'>{last_node}</div><div class='text-xs text-slate-400'>路由資訊</div>"
    
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

    # 由於 Globalping API 處理需要排隊時間，我們依序對 6 組 IP 發起測速
    for ip in IPS:
        print(f"正在透過 Globalping 呼叫台灣探針巡檢 IP: {ip} ...")
        tr_out = fetch_globalping_traceroute(ip)
        
        log_path = LOG_DIR / f"{ip}.log"
        log_path.write_text(f"=== {now} Globalping (Taiwan Node) to {ip} ===\n\n{tr_out}\n", encoding='utf-8')

        hop, last_ip = parse_globalping_mtr(tr_out)
        current = {"hop": hop, "ip": last_ip, "raw": tr_out, "ts": now}
        bl = baseline.get(ip)
        
        meta = meta_map[ip]
        if bl is None:
            if current['hop'] > 0:
                baseline[ip] = {"hop": current['hop'], "ip": current['ip'], "created": now}
                save_baseline(baseline)
            ok_count += 1
            row = build_row_html(ip, meta["net"], meta["comp"], meta["group"], None, current)
        else:
            if current['ip'] and bl.get('ip') and current['ip'] == bl.get('ip'):
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
    print(f"巡檢完成。成功: {ok_count}, 異常: {bad_count}")

if __name__ == "__main__":
    main()
