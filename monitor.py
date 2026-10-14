import os
import json
import re
import sys
import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# 引入 scapy 網路套件（需在 actions 中 pip install scapy）
# 停用 scapy 的警告訊息，保持 log 乾淨
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, sr1

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
BR_NAME = "2L3BR3"

LOG_DIR.mkdir(parents=True, exist_ok=True)

def python_tcp_traceroute(ip, port=80, max_hops=20):
    """
    使用純 Python Scapy 實作的 TCP Traceroute
    可以在 GitHub Actions 的嚴格環境下穿透並抓取 Hops
    """
    log_lines = []
    log_lines.append(f"traceroute to {ip}, {max_hops} hops max, via Python TCP Port {port}")
    
    last_ip = None
    last_hop = 0
    
    for ttl in range(1, max_hops + 1):
        # 建立一個合法的 TCP SYN 封包，並逐次遞增 TTL
        pkt = IP(dst=ip, ttl=ttl) / TCP(dport=port, flags="S")
        
        # 發送封包並等待回應 (等待 1.5 秒)
        reply = sr1(pkt, verbose=0, timeout=1.5)
        
        if reply is None:
            log_lines.append(f" {ttl}  *")
        else:
            hop_ip = reply.src
            log_lines.append(f" {ttl}  {hop_ip}")
            last_hop = ttl
            last_ip = hop_ip
            
            # 如果回應的來源 IP 就是目標 IP，代表已經安全抵達終點，提早結束
            if hop_ip == ip:
                break
                
    return last_hop, last_ip, "\n".join(log_lines)

def load_baseline():
    if BASELINE_FILE.exists():
        try: return json.loads(BASELINE_FILE.read_text(encoding='utf-8'))
        except: return {}
    return {}

def save_baseline(data):
    BASELINE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')

def build_row_html(ip, net, component, nat_group, baseline, current, br_name=BR_NAME):
    if baseline is None:
        diff_text = "(基準建立)"
        judgement = ("text-emerald-400", "✓", "基準建立")
        reached_br = ("text-emerald-400", "✓", br_name)
    else:
        diff = current['hop'] - baseline['hop'] if baseline and current['hop'] is not None else 0
        diff_sign = f"{'+' if diff>0 else ''}{diff}"
        if current['ip'] and baseline.get('ip') and (current['ip'] == baseline.get('ip')):
            reached_br = ("text-emerald-400", "✓", br_name)
            judgement = ("text-emerald-400", "✓", "正常")
            status_text = f"正常抵達 {br_name} ({diff_sign})"
        else:
            reached_br = ("text-rose-400", "✕", "未抵達 BR")
            judgement = ("text-rose-400", "✕", "異常")
            status_text = f"最後回應 {current['ip']}" if current['ip'] else "無回應 / 未抵達 BR"

    ip_cell = f"<div class='text-sm ip-mono text-cyan-300 font-semibold'>{ip}</div><div class='text-xs text-slate-400'>{net}</div>"
    component_cell = f"<div class='text-sm'>{component}</div><div class='text-xs text-slate-400'>{nat_group}</div>"
    
    if baseline is None:
        hop_cell = f"<div class='text-sm font-medium'>{current['hop'] if current['hop'] else '-'}</div><div class='text-xs text-slate-400'>(基準建立)</div>"
        status_text = "基準已建立"
    else:
        diff = current['hop'] - baseline['hop'] if current['hop'] is not None else 0
        diff_sign = f"{'+' if diff>0 else ''}{diff}"
        hop_cell = f"<div class='text-sm font-medium'>{current['hop'] if current['hop'] is not None else '-'}</div><div class='text-xs text-slate-400'>(基:{baseline['hop']} / 差:{diff_sign})</div>"
        
    last_node = current['ip'] if current['ip'] else "<span class='text-rose-300'>無回應</span>"
    last_node_cell = f"<div class='text-sm ip-mono text-sky-400 font-medium'>{last_node}</div><div class='text-xs text-slate-400'>路由資訊</div>"
    
    reached_cls, reached_icon, reached_label = reached_br if baseline is not None else ("text-emerald-400","✓", br_name)
    reached_cell = f"<div class='inline-flex items-center gap-2 {reached_cls} font-medium'><svg class='w-4 h-4' fill='none' stroke='currentColor' stroke-width='2' viewBox='0 0 24 24'><path stroke-linecap='round' stroke-linejoin='round' d='{ 'M5 13l4 4L19 7' if reached_icon=='✓' else 'M6 18L18 6M6 6l12 12' }' /></svg><span>{reached_label}</span></div>"
    
    status_cell = f"<div class='text-sm'>{status_text}</div>"
    judgement_cls, judgement_icon, judgement_label = judgement if baseline is not None else ("text-emerald-400","✓","基準")
    judgement_cell = f"<div class='inline-flex items-center gap-2 {judgement_cls} font-semibold'><span>{judgement_icon}</span><span>{judgement_label}</span></div>"

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

def worker(ip):
    """供執行緒池呼叫的單一任務"""
    hop, last_ip, tr_out = python_tcp_traceroute(ip)
    return ip, hop, last_ip, tr_out

def main():
    baseline = load_baseline()
    results = {}
    rows = []
    ok_count = 0
    bad_count = 0
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    meta_map = {
        "111.71.0.8": ("111.71.0.0/17 (前半)", "3L1EPG1", "NAT7/8"),
        "111.71.212.8": ("111.71.212.0/23 (前半)", "2L3EPG1", "NAT7/8"),
        "111.71.213.8": ("111.71.212.0/23 (後半)", "2L3EPG1", "NAT7/8"),
        "111.71.214.8": ("111.71.214.0/23 (前半)", "3L1EPG1", "NAT7/8"),
        "111.71.215.8": ("111.71.214.0/23 (後半)", "3L1EPG1", "NAT7/8"),
        "111.71.64.8": ("111.71.64.0/24", "3L1EPG6", "NAT7/8"),
    }

    # 在 GitHub Actions 環境中，因為 scapy 的 Socket 建立需要 root，平行處理要謹慎。
    # 這裡我們一樣採用 6 個 threads 平行探測
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(worker, ip) for ip in IPS]
        
    for f in futures:
        ip, hop, last_ip, tr_out = f.result()
        
        log_path = LOG_DIR / f"{ip}.log"
        log_path.write_text(f"=== {now} Python TCP Traceroute to {ip} ===\n\n{tr_out}\n", encoding='utf-8')

        current = {"hop": hop, "ip": last_ip, "raw": tr_out, "ts": now}
        bl = baseline.get(ip)
        
        if bl is None:
            baseline[ip] = {"hop": current['hop'], "ip": current['ip'], "created": now}
            save_baseline(baseline)
            ok_count += 1
            row = build_row_html(ip, meta_map[ip][0], meta_map[ip][1], meta_map[ip][2], None, current)
        else:
            if current['ip'] and bl.get('ip') and current['ip'] == bl.get('ip'):
                ok_count += 1
            else:
                bad_count += 1
            row = build_row_html(ip, meta_map[ip][0], meta_map[ip][1], meta_map[ip][2], bl, current)
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

if __name__ == "__main__":
    main()
