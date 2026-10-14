#!/usr/bin/env python3
"""
tracer_monitor.py
- 針對固定 IP 清單執行 traceroute
- 若 baseline.json 中沒有該 IP，將本次結果視為基準並儲存
- 否則比對 hop 數與 last-hop IP，計算差值與判定（正常/異常）
- 將結果填入 index_template.html 的 <!-- TABLE_ROWS -->，輸出 index.html
- 也會把 traceroute 原始輸出保存到 logs/{ip}.log（供「查看」按鈕使用）
"""

import subprocess, json, re, os, sys, datetime
from pathlib import Path

# 使用者可修改的區域
BASE_DIR = Path(__file__).resolve().parent
TEMPLATE = BASE_DIR / "index_template.html"
OUTPUT = BASE_DIR / "index.html"
BASELINE_FILE = BASE_DIR / "baseline.json"
LOG_DIR = BASE_DIR / "logs"
IPS = [
    "111.71.0.8",
    "111.71.212.8",
    "111.71.213.8",
    "111.71.214.8",
    "111.71.215.8",
    "111.71.64.8"
]
BR_NAME = "2L3BR3"   # 若達到基準的最後一跳，顯示的 BR 名稱（可自行修改）
TRACEROUTE_CMD = ["sudo","traceroute", "-n", "-T", "-p", "80", "-w", "2", "-q", "1", "-m", "20"]  # 假設 Linux 環境

# 確保 log 目錄存在
LOG_DIR.mkdir(parents=True, exist_ok=True)

def run_traceroute(ip):
    cmd = TRACEROUTE_CMD + [ip]
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
        out = p.stdout + ("\nERR:\n" + p.stderr if p.stderr else "")
    except Exception as e:
        out = f"Exception running traceroute: {e}"
    return out

def parse_last_hop(tr_out):
    """
    解析 traceroute 結果，回傳 (hop_count (int), last_hop_ip (str or None))
    規則：掃描每一行，找到含 IP 的最後一行，取其 hop number 與 IP。
    若沒有任何回應（全 *），回傳 (0, None)
    """
    last_ip = None
    last_hop = 0
    # matches lines like: " 1  10.0.0.1  1.123 ms" or " 3  203.69.22.10  12.34 ms"
    ip_re = re.compile(r"^\s*(\d+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")
    for line in tr_out.splitlines():
        m = ip_re.match(line)
        if m:
            hop = int(m.group(1))
            ip = m.group(2)
            last_hop = hop
            last_ip = ip
    return last_hop, last_ip

def load_baseline():
    if BASELINE_FILE.exists():
        try:
            return json.loads(BASELINE_FILE.read_text(encoding='utf-8'))
        except Exception:
            return {}
    return {}

def save_baseline(data):
    BASELINE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')

def build_row_html(ip, net, component, nat_group, baseline, current, br_name=BR_NAME):
    """
    baseline: dict or None: {'hop':int,'ip':str,'created':...}
    current: dict: {'hop':int,'ip':str,'raw':...,'ts':...}
    返回對應的 <tr> HTML
    """
    # 判定與樣式
    if baseline is None:
        diff_text = "(基準建立)"
        judgement = ("text-emerald-400", "✓", "基準建立")
        reached_br = ("text-emerald-400", "✓", br_name)
    else:
        diff = current['hop'] - baseline['hop'] if baseline and current['hop'] is not None else 0
        diff_sign = f"{'+' if diff>0 else ''}{diff}"
        diff_text = f"{current['hop']}<div class='text-xs text-slate-400'>(基:{baseline['hop']} / 差:{diff_sign})</div>"
        # 是否抵達 BR（以 last hop IP 是否與 baseline ip 相同判定）
        if current['ip'] and baseline.get('ip') and (current['ip'] == baseline.get('ip')):
            reached_br = ("text-emerald-400", "✓", br_name)
            judgement = ("text-emerald-400", "✓", "正常")
            status_text = f"正常抵達 {br_name} ({diff_sign})"
        else:
            # 異常：最後一跳不同或沒有回應
            reached_br = ("text-rose-400", "✕", "未抵達 BR")
            judgement = ("text-rose-400", "✕", "異常")
            if current['ip']:
                status_text = f"最後回應 {current['ip']} (基: {baseline.get('ip')})"
            else:
                status_text = "無回應 / 未抵達 BR"
    # Prepare cells
    ip_cell = f"<div class='text-sm ip-mono text-cyan-300 font-semibold'>{ip}</div><div class='text-xs text-slate-400'>{net}</div>"
    component_cell = f"<div class='text-sm'>{component}</div><div class='text-xs text-slate-400'>{nat_group}</div>"
    # hop cell: if baseline is None show baseline建立用 current hop as baseline
    if baseline is None:
        hop_cell = f"<div class='text-sm font-medium'>{current['hop'] if current['hop'] else '-'}</div><div class='text-xs text-slate-400'>(基準建立)</div>"
        status_text = "基準已建立"
    else:
        diff = current['hop'] - baseline['hop'] if current['hop'] is not None else 0
        diff_sign = f"{'+' if diff>0 else ''}{diff}"
        hop_cell = f"<div class='text-sm font-medium'>{current['hop'] if current['hop'] is not None else '-'}</div><div class='text-xs text-slate-400'>(基:{baseline['hop']} / 差:{diff_sign})</div>"
    # last node cell
    last_node = current['ip'] if current['ip'] else "<span class='text-rose-300'>無回應</span>"
    last_node_cell = f"<div class='text-sm ip-mono text-sky-400 font-medium'>{last_node}</div><div class='text-xs text-slate-400'>路由資訊</div>"
    # reached BR cell
    reached_cls, reached_icon, reached_label = reached_br if baseline is not None else ("text-emerald-400","✓", br_name)
    reached_cell = f"<div class='inline-flex items-center gap-2 {reached_cls} font-medium'><svg class='w-4 h-4' fill='none' stroke='currentColor' stroke-width='2' viewBox='0 0 24 24'><path stroke-linecap='round' stroke-linejoin='round' d='{ 'M5 13l4 4L19 7' if reached_icon=='✓' else 'M6 18L18 6M6 6l12 12' }' /></svg><span>{reached_label}</span></div>"
    # status text cell
    status_cell = f"<div class='text-sm'>{status_text}</div>"
    # judgement
    judgement_cls, judgement_icon, judgement_label = judgement if baseline is not None else ("text-emerald-400","✓","基準")
    judgement_cell = f"<div class='inline-flex items-center gap-2 {judgement_cls} font-semibold'><span>{judgement_icon}</span><span>{judgement_label}</span></div>"

    # "查看" button links to logs/{ip}.log (腳本會產生)
    log_file = f"logs/{ip}.log"
    view_btn = f"<a class='px-3 py-1 text-sm text-sky-500 bg-sky-900/30 rounded-md hover:bg-sky-800/40 transition' href='{log_file}' target='_blank'>查看</a>"

    row_html = f"""
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
    return row_html

def main():
    baseline = load_baseline()
    results = {}
    rows = []
    ok_count = 0
    bad_count = 0
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # For demonstration we set per-IP metadata like net / component / nat_group; in production these可從 DB 或 config 取得
    meta_map = {
        "111.71.0.8": ("111.71.0.0/24", "3L1EPG1", "NAT 群組 A"),
        "111.71.212.8": ("111.71.212.0/24", "3L1EPG2", "NAT 群組 B"),
        "111.71.213.8": ("111.71.213.0/24", "3L1EPG3", "NAT 群組 C"),
        "111.71.214.8": ("111.71.214.0/24", "3L1EPG4", "NAT 群組 D"),
        "111.71.215.8": ("111.71.215.0/24", "3L1EPG5", "NAT 群組 E"),
        "111.71.64.8": ("111.71.64.0/24", "3L1EPG6", "NAT 群組 F"),
    }

    for ip in IPS:
        tr_out = run_traceroute(ip)
        # 儲存原始 traceroute 到 logs
        log_path = LOG_DIR / f"{ip}.log"
        tstamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_path.write_text(f"=== {tstamp} traceroute to {ip} ===\n\n{tr_out}\n", encoding='utf-8')

        hop, last_ip = parse_last_hop(tr_out)
        current = {"hop": hop if hop else 0, "ip": last_ip, "raw": tr_out, "ts": tstamp}

        # 比較 baseline
        bl = baseline.get(ip)
        if bl is None:
            # 建立基準
            baseline[ip] = {"hop": current['hop'], "ip": current['ip'], "created": tstamp}
            save_baseline(baseline)
            # treat as OK baseline established
            ok_count += 1
            row = build_row_html(ip, meta_map[ip][0], meta_map[ip][1], meta_map[ip][2], None, current)
        else:
            # 做差值與判定
            if current['ip'] and bl.get('ip') and current['ip'] == bl.get('ip'):
                ok_count += 1
            else:
                bad_count += 1
            row = build_row_html(ip, meta_map[ip][0], meta_map[ip][1], meta_map[ip][2], bl, current)
        rows.append(row)
        results[ip] = {"baseline": baseline.get(ip), "current": current}

    # 將 rows 塞回 template
    if not TEMPLATE.exists():
        print("Template file not found:", TEMPLATE, file=sys.stderr)
        sys.exit(1)
    tpl = TEMPLATE.read_text(encoding='utf-8')
    rows_html = "\n".join(rows)
    out_html = tpl.replace("<!-- TABLE_ROWS -->", rows_html)

    # 在頁面內注入簡單 meta object（讓 client-side JS 顯示統計）
    meta_js = f"<script>window.__MONITOR_META__ = {{ last_updated: '{now}', total: {len(IPS)}, ok: {ok_count}, bad: {bad_count} }};</script>\n"
    # 把 meta_js 放在 </head> 前（或 body 前）。我們簡單插到 <body> 開頭。
    out_html = out_html.replace("<body", f"{meta_js}<body", 1)

    OUTPUT.write_text(out_html, encoding='utf-8')
    # 寫入 baseline.json 已在建立時處理
    # 另外可寫入 results.json 供其他系統查閱
    (BASE_DIR / "results.json").write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding='utf-8')

    print(f"[{now}] Done. Output: {OUTPUT}. OK={ok_count}, BAD={bad_count}")

if __name__ == "__main__":
    main()
