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

IPS = ["2001:B400:E200::1", "2001:B400:E250::1", "2001:B400:E2A0::1", "2001:B400:E260::1", 
       "2001:B400:E300::1", "2001:B400:E350::1", "2001:B400:E3A0::1", "2001:B400:E3E0::1",
       "2001:B400:E400::1", "2001:B400:E450::1", "2001:B400:E4A0::1", "2001:B400:E500::1",   
       "2001:B400:E700::1", "2001:B400:E750::1", "2001:B400:E7A0::1", "2001:B400:E600::1", 
      ]
# 中華電信行動網路 IPv6 核心骨幹預期正確網段
EXPECTED_LAST_HOP_PATTERN = r"^2001:b400:15[678]:"
EXPECTED_LAST_HOP_PATTERN2 = r"^2001:b000:80:[08]:"

BR_NAME = "CHTM BR"

LOG_DIR.mkdir(parents=True, exist_ok=True)

def fetch_globalping_traceroute_official(target):
    """
    100% 採用您提供之同事黃金源碼通訊機制與正確 API 網址
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
    智能路由解析器：
    自動過濾掉帶有 !N (Network Unreachable) 的錯誤終點行，
    由下往上逆向尋找第一個真正有效回應的核心骨幹路由器 IP。
    """
    lines = raw_out.splitlines()
    
    # 匹配跳數與括號內 IP 的標準正則
    ip_in_parentheses_re = re.compile(r"^\s*(\d+)\s+.*?\(([0-9a-fA-F:\.]+)\)")
    
    # 為了實現由下往上找，我們將日誌行數進行反轉（倒序）
    for line in reversed(lines):
        # ✨ 核心安全鎖：如果這一行包含 !N 或是其他不可達標記，直接丟棄不解析 ✨
        if "!N" in line or "!H" in line or "!P" in line:
            print(f"[異常封包過濾] 已自動剔除帶有不可達標記的行數: {line.strip()}")
            continue
            
        m = ip_in_parentheses_re.match(line)
        if m:
            hop = int(m.group(1))
            ip = m.group(2)
            # 找到最底層、第一個沒有錯誤標記的實體節點，立刻回傳（這就是真正的 Last Hop）
            return hop, ip
            
    return 0, None

def load_baseline():
    if BASELINE_FILE.exists():
        try: return json.loads(BASELINE_FILE.read_text(encoding='utf-8'))
        except: return {}
    return {}

def save_baseline(data):
    BASELINE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')

def build_row_html(ip, net, component, nat_group, baseline, current, route_status, br_name="CHTM BR", epg_name="CHTM EPG"):
    """
    修改重點：支援 EPG 與 BR 雙重成功路徑的判斷，並動態顯示對應標籤。
    """
    is_valid_route = route_status in ["EPG", "BR"]

    if route_status == "EPG":
        reached_br = ("text-emerald-400", "✓", epg_name)
        status_text_base = f"抵達 {epg_name}"
    elif route_status == "BR":
        reached_br = ("text-cyan-400", "✓", br_name) # 使用不同顏色區分
        status_text_base = f"抵達 {br_name}"
    else:
        reached_br = ("text-rose-400", "✕", "未抵達")
        status_text_base = "路由中斷/異常"

    if baseline is None:
        hop_cell = f"<div class='text-sm font-medium text-white'>{current['hop'] if current['hop'] else '-'}</div><div class='text-xs text-slate-400'>(新基準建立)</div>"
        status_text = "新項目基準已建立" if is_valid_route else status_text_base
        judgement = ("text-emerald-400", "✓", "正常") if is_valid_route else ("text-rose-400", "✕", "錯誤")
    else:
        diff = current['hop'] - baseline['hop'] if current['hop'] is not None and baseline.get('hop') is not None else 0
        diff_sign = f"+{diff}" if diff > 0 else f"{diff}"
        diff_cls = "text-amber-400" if diff != 0 else "text-slate-400"
        hop_cell = f"<div class='text-sm font-medium text-white'>{current['hop'] if current['hop'] is not None else '-'}</div><div class='text-xs {diff_cls}'>(基:{baseline['hop']} / 差:{diff_sign})</div>"

        if is_valid_route:
            judgement = ("text-emerald-400", "✓", "正常")
            status_text = f"{status_text_base} ({diff_sign})"
        else:
            judgement = ("text-rose-400", "✕", "錯誤")
            status_text = f"回應: {current['ip'] if current['ip'] else '無回應'}"

    ip_cell = f"<div class='text-sm ip-mono text-sky-300 font-semibold'>{ip}</div><div class='text-xs text-slate-400'>{net}</div>"
    component_cell = f"<div class='text-sm text-slate-100 font-medium'>{component}</div><div class='text-xs text-slate-400'>{nat_group}</div>"

    last_node = current['ip'] if current['ip'] else "<span class='text-rose-400 font-medium'>* * *</span>"
    last_node_cell = f"<div class='text-sm ip-mono text-violet-300 font-medium'>{last_node}</div><div class='text-xs text-slate-400'>最後一跳</div>"

    reached_cls, _, reached_label = reached_br
    # EPG 使用 emerald, BR 使用 cyan
    reached_color_cls = "text-cyan-400" if route_status == "BR" else "text-emerald-400"
    reached_cell = f"<div class='inline-flex items-center gap-2 {reached_color_cls} font-medium'><span>{reached_label}</span></div>"

    status_cell = f"<div class='text-sm text-slate-100'>{status_text}</div>"
    judgement_cls, _, judgement_label = judgement
    judgement_cell = f"<div class='inline-flex items-center gap-2 {judgement_cls} font-semibold'><span>{judgement_label}</span></div>"
    log_file = f"logs/{ip}.log"
    view_btn = f"<a class='px-3 py-1 text-xs text-cyan-300 bg-cyan-950/60 border border-cyan-800/50 rounded-md hover:bg-cyan-900/80 transition' href='{log_file}' target='_blank'>查看</a>"

    return f"""
    <tr class="hover:bg-slate-800/40 transition-colors duration-200 border-b border-slate-800/50 text-slate-300">
      <td class="px-6 py-4">{ip_cell}</td>
      <td class="px-6 py-4">{component_cell}</td>
      <td class="px-6 py-4 text-center">{hop_cell}</td>
      <td class="px-6 py-4">{last_node_cell}</td>
      <td class="px-6 py-4">{reached_cell}</td>
      <td class="px-6 py-4">{status_cell}</td>
      <td class="px-4 py-4 text-center">{judgement_cell}</td>
      <td class="px-6 py-4 text-center">{view_btn}</td>
    </tr>
    """

def main():
    # 更新正規表示式
    EXPECTED_LAST_HOP_PATTERN = r"^2001:b400:15[6789]:"
    EXPECTED_LAST_HOP_PATTERN2 = r"^2001:b000:80:[08]:"

    baseline = load_baseline()
    results = {}
    rows = []
    ok_count = 0
    bad_count = 0
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    meta_map = {
        "2001:B400:E200::1": {"net": "IPv6 網段巡檢", "comp": "2L3EPG1", "group": ""},
        "2001:B400:E250::1": {"net": "IPv6 網段巡檢", "comp": "2L3EPG2", "group": ""},
        "2001:B400:E2A0::1": {"net": "IPv6 網段巡檢", "comp": "2L3EPG3", "group": ""},
        "2001:B400:E260::1": {"net": "IPv6 網段巡檢", "comp": "2L3EPG4", "group": ""},
        "2001:B400:E300::1": {"net": "IPv6 網段巡檢", "comp": "3L1EPG1", "group": ""},
        "2001:B400:E350::1": {"net": "IPv6 網段巡檢", "comp": "3L1EPG2", "group": ""},
        "2001:B400:E3A0::1": {"net": "IPv6 網段巡檢", "comp": "3L1EPG3", "group": ""},
        "2001:B400:E3E0::1": {"net": "IPv6 網段巡檢", "comp": "3L1EPG4U", "group": ""},
        "2001:B400:E400::1": {"net": "IPv6 網段巡檢", "comp": "4L1EPG1", "group": ""},
        "2001:B400:E450::1": {"net": "IPv6 網段巡檢", "comp": "4L1EPG2", "group": ""},
        "2001:B400:E4A0::1": {"net": "IPv6 網段巡檢", "comp": "4L1EPG3", "group": ""},
        "2001:B400:E500::1": {"net": "IPv6 網段巡檢", "comp": "CHCH", "group": ""},
        "2001:B400:E700::1": {"net": "IPv6 網段巡檢", "comp": "7L2EPG1", "group": ""},
        "2001:B400:E750::1": {"net": "IPv6 網段巡檢", "comp": "7L2EPG2", "group": ""},
        "2001:B400:E7A0::1": {"net": "IPv6 網段巡檢", "comp": "7L2EPG3", "group": ""},
        "2001:B400:E600::1": {"net": "IPv6 網段巡檢", "comp": "TNE1", "group": ""},
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

        # 新的路由狀態判斷邏輯
        route_status = "FAIL" # Default
        if current['ip']:
            if bool(re.match(EXPECTED_LAST_HOP_PATTERN, current['ip'], re.IGNORECASE)):
                route_status = "EPG"
            elif bool(re.match(EXPECTED_LAST_HOP_PATTERN2, current['ip'], re.IGNORECASE)):
                route_status = "BR"

        # 統計卡片數值更新
        if route_status in ["EPG", "BR"]:
            ok_count += 1
        else:
            bad_count += 1

        is_valid_route = route_status in ["EPG", "BR"]
        if bl is None:
            if is_valid_route and current['hop'] > 0:
                baseline[ip] = {"hop": current['hop'], "ip": current['ip'], "created": now}
                save_baseline(baseline)
            row = build_row_html(ip, meta["net"], meta["comp"], meta["group"], None, current, route_status)
        else:
            row = build_row_html(ip, meta["net"], meta["comp"], meta["group"], bl, current, route_status)

        rows.append(row)
        results[ip] = {"baseline": baseline.get(ip), "current": current}

    if not TEMPLATE.exists():
        print(f"錯誤: 找不到模板檔案 {TEMPLATE}")
        sys.exit(1)

    tpl = TEMPLATE.read_text(encoding='utf-8')
    rows_html = "\n".join(rows)
    out_html = tpl.replace("<!-- TABLE_ROWS -->", rows_html)

    meta_js = f"<script>window.__MONITOR_META__ = {{ last_updated: '{now}', total: {len(IPS)}, ok: {ok_count}, bad: {bad_count} }};</script>\n"
    out_html = out_html.replace("<body", f"{meta_js}<body", 1)

    OUTPUT.write_text(out_html, encoding='utf-8')
    (BASE_DIR / "results.json").write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"IPv6 巡檢完成。正常(綠燈): {ok_count}, 異常(紅燈): {bad_count}")

if __name__ == "__main__":
    main()
