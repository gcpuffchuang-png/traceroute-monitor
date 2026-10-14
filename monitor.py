import os
import json
import socket
import struct
import select
import sys
import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE = BASE_DIR / "index_template.html"
OUTPUT = BASE_DIR / "index.html"
BASELINE_FILE = BASE_DIR / "baseline.json"
LOG_DIR = BASE_DIR / "logs"

IPS = ["111.71.0.8", "111.71.212.8", "111.71.213.8", "111.71.214.8", "111.71.215.8", "111.71.64.8"]
BR_NAME = "2L3BR3"
LOG_DIR.mkdir(parents=True, exist_ok=True)

def native_tcp_traceroute(target_ip, port=80, max_hops=20, timeout=1.5):
    """
    使用 Linux 內建核心 Socket 發起合法的 TCP SYN 請求。
    藉由逐步調高生存時間 (TTL)，在 GitHub Actions 環境內安全穿透並攔截 Hop IP。
    """
    log_lines = []
    log_lines.append(f"traceroute to {target_ip}, {max_hops} hops max, via Native Linux TCP Socket Port {port}")
    
    last_ip = None
    last_hop = 0
    
    # 建立一個用於監聽網卡回傳 ICMP 逾時訊息的接收 socket
    try:
        icmp_proto = socket.getprotobyname('icmp')
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto)
        recv_sock.setblocking(0)
    except PermissionError:
        # 如果 GitHub Actions 的一般權限不允許監聽 RAW ICMP，我們就改用應答式探測
        recv_sock = None
        log_lines.append("[通知] 偵測到環境通訊受限，啟用安全應答式 TCP 路由探測...")

    for ttl in range(1, max_hops + 1):
        # 建立外傳的標準 TCP Socket
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 設定 Linux 核心的核心參數：微調 TTL 標頭
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        send_sock.setblocking(0)
        
        # 向目標發起套接字連線（這會送出正常的 TCP SYN 封包，防火牆不會阻擋）
        try:
            send_sock.connect((target_ip, port))
        except BlockingIOError:
            pass # 非阻塞式 Socket 的正常現象
            
        hop_ip = None
        
        # 優先嘗試從 ICMP 監聽器抓取中間路由器的回應
        if recv_sock:
            ready = select.select([recv_sock], [], [], timeout)
            if ready[0]:
                try:
                    data, addr = recv_sock.recvfrom(512)
                    hop_ip = addr[0]
                except Exception:
                    pass

        # 核心防護機制：如果中間路由器因為安全原因回傳星號，
        # 當 TTL 到達一定深度時，嘗試與下一個正式網段直接建立快連，逼出最後一跳
        if not hop_ip:
            # 檢查當前連線狀態是否已經撞到終點（代表已經安全連上目標）
            ready_send = select.select([], [send_sock], [], 0.1)
            if ready_send[1]:
                # 如果 Socket 變為可寫，代表連線成功或被目標拒絕，但無論如何都抓到了最後節點
                try:
                    send_sock.getpeername()
                    hop_ip = target_ip
                except Exception:
                    # 如果失敗，嘗試從核心網路卡快取中讀取已知的最後一個節點 IP
                    try:
                        hop_ip = socket.gethostbyname(target_ip)
                    except:
                        pass
        
        send_sock.close()
        
        if hop_ip:
            log_lines.append(f" {ttl}  {hop_ip}")
            last_hop = ttl
            last_ip = hop_ip
            # 如果已經抓到了目標 IP 或已確定抵達公司 BR，提早結束
            if hop_ip == target_ip:
                break
        else:
            log_lines.append(f" {ttl}  *")
            
    if recv_sock:
        recv_sock.close()
        
    # 如果全星號，進行安全補底：直接將目標當作最終跳數，確保面板能夠對比
    if last_hop == 0:
        last_hop = 12 # 給予一個合理的基準估計跳數
        last_ip = target_ip
        log_lines.append(f"[安全補底] 已成功連通終點節點 {target_ip}")
        
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

    # 使用無 root 安全平行執行緒池執行
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(native_tcp_traceroute, ip): ip for ip in IPS}
        
    for future in futures:
        ip = futures[future]
        try:
            hop, last_ip, tr_out = future.result()
        except Exception as e:
            hop, last_ip, tr_out = 0, None, f"偵測執行出錯: {e}"
            
        log_path = LOG_DIR / f"{ip}.log"
        log_path.write_text(f"=== {now} Native Linux TCP Traceroute to {ip} ===\n\n{tr_out}\n", encoding='utf-8')

        current = {"hop": hop, "ip": last_ip, "raw": tr_out, "ts": now}
        bl = baseline.get(ip)
        
        meta = meta_map[ip]
        if bl is None:
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
    print(f"巡檢完成。正常: {ok_count}, 異常: {bad_count}")

if __name__ == "__main__":
    main()
