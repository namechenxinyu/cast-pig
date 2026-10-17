#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""投屏猪 (Cast Pig) — 把电脑屏幕/视频投到局域网内的 DLNA 电视、投影仪。

单文件, 无需安装。依赖: Python3 + tkinter(自带) + ffmpeg。
Linux: 屏幕=x11grab, 声音=parec 管道; Windows: 屏幕=gdigrab, 声音=dshow(立体声混音)。
ffmpeg 查找顺序: 本目录 ffmpeg(.exe) → 系统 PATH。
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class _CastHTTPServer(ThreadingHTTPServer):
    """加大连接队列: 投影仪每秒都来取切片, 网络抖动时请求可能瞬间堆积"""
    request_queue_size = 64
    daemon_threads = True
from xml.sax.saxutils import escape

IS_WIN = (os.name == "nt")
APP_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION = open(os.path.join(APP_DIR, "VERSION")).read().strip() if \
    os.path.isfile(os.path.join(APP_DIR, "VERSION")) else "dev"
PORT = 8912
# 常见 DLNA 候选端口(UPnP 端口动态分配, 这里只是加速线索; 找不到时上级兜底)
FAST_PORTS = (25826, 49152, 49153, 49154, 49155, 49156, 7100)
AUDIO_FIFO = os.path.join(tempfile.gettempdir(), "cast_pig_audio.fifo")
STATIC_TS = os.path.join(tempfile.gettempdir(), "cast_pig_file.ts")

# ---------------- 设置(记住上次设备/模式, 实现一键直连) ----------------

def _settings_path():
    if os.access(APP_DIR, os.W_OK):
        return os.path.join(APP_DIR, "settings.json")
    return os.path.expanduser("~/.cast_pig_settings.json")   # 目录只读时(如U盘)

def load_settings():
    for p in (_settings_path(),
              os.path.expanduser("~/.cast_app_settings.json")):   # 旧版兼容
        try:
            with open(p) as f:
                return json.load(f)
        except Exception:
            continue
    return {}

def save_settings(d):
    try:
        with open(_settings_path(), "w") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
    except OSError:
        pass

def find_ffmpeg():
    """ffmpeg 查找: 环境变量 → 本目录 → PATH"""
    name = "ffmpeg.exe" if IS_WIN else "ffmpeg"
    local = os.path.join(APP_DIR, name)
    if os.path.isfile(local):
        return local
    return name   # 交给 PATH

FFMPEG = find_ffmpeg()

# ---------------- 设备发现 ----------------

def _avtransport_from_desc(desc_url):
    """从设备描述 XML 提取 {name, ctrl, model}"""
    try:
        with urllib.request.urlopen(desc_url, timeout=2.5) as r:
            xml = r.read().decode(errors="replace")
    except Exception:
        return None
    if "AVTransport" not in xml:
        return None
    m = re.search(r"<friendlyName>(.*?)</friendlyName>", xml, re.S)
    name = m.group(1).strip() if m else desc_url
    mm = re.search(r"<modelName>(.*?)</modelName>", xml, re.S)
    model = mm.group(1).strip() if mm else ""
    ctrl = None
    for block in re.findall(r"<service>.*?</service>", xml, re.S):
        if "AVTransport" in block:
            cm = re.search(r"<controlURL>(.*?)</controlURL>", block, re.S)
            if cm:
                ctrl = cm.group(1).strip()
                break
    if not ctrl:
        return None
    if not ctrl.startswith("http"):
        base_m = re.search(r"<URLBase>(.*?)</URLBase>", xml)
        base = base_m.group(1).strip() if base_m else desc_url.rsplit("/", 1)[0]
        ctrl = base.rstrip("/") + "/" + ctrl.lstrip("/")
    return {"name": name, "ctrl": ctrl, "model": model}

def _ssdp_probe(timeout=4.0):
    """SSDP 组播搜索, 返回 {设备描述XML地址: IP}"""
    locations = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        for st in ("urn:schemas-upnp-org:device:MediaRenderer:1", "ssdp:all"):
            msg = ("\r\n".join(["M-SEARCH * HTTP/1.1", "HOST: 239.255.255.250:1900",
                                'MAN: "ssdp:discover"', "MX: 2", f"ST: {st}", ""])).encode()
            s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            for line in data.decode(errors="replace").splitlines():
                if line.upper().startswith("LOCATION:"):
                    locations.setdefault(line.split(":", 1)[1].strip(), addr[0])
    except OSError:
        pass
    return locations

def _probe_host(ip, ports):
    """快速探测某主机上第一个可用的 DLNA 服务。

    先并行探测端口(离线端口 TCP 连接会等满超时, 串行 7 个端口能拖 30 秒),
    只对真正开放的端口读 description.xml。
    """
    import concurrent.futures as cf

    def port_open(p):
        s = socket.socket()
        s.settimeout(0.7)
        try:
            return p if s.connect_ex((ip, p)) == 0 else None
        finally:
            s.close()

    if not ports:
        return None, None
    with cf.ThreadPoolExecutor(max_workers=min(8, len(ports))) as ex:
        open_ports = [p for p in ex.map(port_open, ports) if p]
    for port in open_ports:
        r = _avtransport_from_desc(f"http://{ip}:{port}/description.xml")
        if r:
            return r, port
    return None, None

def _find_ip_by_mac(mac):
    """在 ARP 邻居表中按 MAC 查找设备当前 IP(DHCP 换址后自动找回)"""
    if not mac:
        return None
    mac = mac.replace(":", "").replace("-", "").lower()
    try:
        if IS_WIN:
            out = subprocess.run(["arp", "-a"], capture_output=True, timeout=8)
            text = out.stdout.decode(errors="replace")
        else:
            out = subprocess.run(["ip", "neigh", "show"], capture_output=True, timeout=8)
            text = out.stdout.decode(errors="replace")
        for mm in re.finditer(
                r"(\d+\.\d+\.\d+\.\d+)[^\n]*?((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})",
                text):
            if mm.group(2).replace(":", "").replace("-", "").lower() == mac:
                return mm.group(1)
    except Exception:
        pass
    return None

def _mac_of_ip(ip):
    """从 ARP 邻居表读取某 IP 的 MAC, 记入 settings 供 DHCP 换址后定位"""
    if not ip:
        return ""
    try:
        if IS_WIN:
            out = subprocess.run(["arp", "-a", ip], capture_output=True, timeout=8)
        else:
            out = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, timeout=8)
        text = out.stdout.decode(errors="replace")
        mm = re.search(r"((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})", text)
        return mm.group(1).lower() if mm else ""
    except Exception:
        return ""

def _deep_port_scan(ip, progress=None):
    """全端口扫描单台主机, 找出任意端口上的 DLNA 服务(端口被改后的终极兜底)"""
    from concurrent.futures import ThreadPoolExecutor
    if progress:
        progress(f"深度扫描 {ip} 全部端口(约 1 分钟) ...")

    def chk(p):
        s = socket.socket()
        s.settimeout(0.7)
        try:
            return p if s.connect_ex((ip, p)) == 0 else None
        finally:
            s.close()

    open_ports = []
    with ThreadPoolExecutor(max_workers=350) as ex:
        for r in ex.map(chk, range(1, 65536)):
            if r:
                open_ports.append(r)
    if progress and open_ports:
        progress(f"{ip} 开放端口: {open_ports}")
    found = []
    for p in open_ports:
        r = _avtransport_from_desc(f"http://{ip}:{p}/description.xml")
        if r:
            found.append((r, ip))
    return found

def _lan_prefix():
    """推断真实局域网网段前缀(如 "192.168.1")。

    不能用 my_ip() 无参版本: 开启代理 TUN 时它会返回 198.18.x 虚拟地址,
    导致扫描错误网段。优先用上次设备 IP, 否则枚举本机物理网卡地址。
    """
    last = load_settings().get("last_ctrl", "")
    m = re.match(r"https?://(\d+\.\d+\.\d+)\.", last)
    if m:
        return m.group(1)
    try:
        if IS_WIN:
            out = subprocess.run(["ipconfig"], capture_output=True, timeout=8)
            text = out.stdout.decode(errors="replace")
            for m in re.finditer(r"IPv4[^:]*:\s*(\d+\.\d+\.\d+)\.", text):
                p = m.group(1)
                if not p.startswith(("127.", "169.254.")):
                    return p
        else:
            out = subprocess.run(["ip", "-4", "-o", "addr", "show"],
                                 capture_output=True, timeout=8)
            for line in out.stdout.decode(errors="replace").splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue
                iface = parts[1]
                # 排除回环与虚拟接口(代理 TUN / 容器 / 虚拟机)
                if re.fullmatch(r"(lo|tun\d*|tap\d*|docker\d*|uengine\d*|veth\w+|br-\w+|wg\d*)", iface):
                    continue
                m = re.search(r"inet (\d+\.\d+\.\d+)\.", line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return ".".join(my_ip().split(".")[:3])

def _ping_online(ip, timeout=1.5):
    """快速判断主机是否在线"""
    if IS_WIN:
        args = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        args = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    try:
        return subprocess.run(args, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,
                              timeout=timeout + 1).returncode == 0
    except Exception:
        return False

def _projector_hint_ports(ip):
    """主机是否开有"投影仪特征"端口, 返回端口号; 需内容验证的端口会核验。"""
    # 25826/5555/61949 端口本身就是强特征; 8899 需确认是沙发管家
    for p in (25826, 5555, 61949):
        s = socket.socket()
        s.settimeout(0.8)
        try:
            if s.connect_ex((ip, p)) == 0:
                return p
        finally:
            s.close()
    # 8899: 很多设备(如小米音箱)也开这个端口, 必须验证 HTTP 内容
    s = socket.socket()
    s.settimeout(0.8)
    try:
        opened = s.connect_ex((ip, 8899)) == 0
    finally:
        s.close()
    if opened:
        try:
            with urllib.request.urlopen(f"http://{ip}:8899/", timeout=3) as r:
                body = r.read(4096).decode(errors="replace")
            if "沙发管家" in body or "shafa" in body.lower():
                return 8899
        except Exception:
            pass
    return None

def _find_suspects(progress=None):
    """全子网找"像投影仪"但没开 DLNA 的设备, 用于给出可操作诊断提示"""
    from concurrent.futures import ThreadPoolExecutor
    prefix = _lan_prefix()
    suspects = []

    def probe(i):
        ip = f"{prefix}.{i}"
        port = _projector_hint_ports(ip)
        return (ip, port) if port else None

    try:
        with ThreadPoolExecutor(max_workers=128) as ex:
            for r in ex.map(probe, range(1, 255)):
                if r:
                    suspects.append(r)
    except Exception:
        pass
    if progress:
        for ip, port in suspects:
            progress(f"  疑似投屏设备: {ip} (开放端口 {port})")
    return suspects

def _subnet_scan(ports=(25826, 49152, 49153, 49154), progress=None):
    """并发扫描本网段, 找支持 DLNA 的设备(用于不响应 SSDP 的型号)。

    直接对全部 254 个 IP 做短超时端口探测(约 2~4 秒), **不用 ping 预筛**:
    投影仪等设备常屏蔽 ICMP 或省电时不响应 ping, 用 ping 筛会漏掉真实设备
    (v1.5.1 曾因此引入"设备在网却扫不到"的回归)。
    """
    from concurrent.futures import ThreadPoolExecutor
    prefix = _lan_prefix()
    if progress:
        progress(f"扫描网段 {prefix}.0/24 ...")
    ips = [f"{prefix}.{i}" for i in range(1, 255)]

    def probe_port(args):
        ip, p = args
        s = socket.socket()
        s.settimeout(0.35)
        try:
            return (ip, p) if s.connect_ex((ip, p)) == 0 else None
        finally:
            s.close()

    tasks = [(ip, p) for ip in ips for p in ports]
    opened = []
    with ThreadPoolExecutor(max_workers=400) as ex:
        for r in ex.map(probe_port, tasks):
            if r:
                opened.append(r)

    hits, seen = [], set()
    for ip, port in opened:
        if ip in seen:
            continue
        r = _avtransport_from_desc(f"http://{ip}:{port}/description.xml")
        if r:
            seen.add(ip)
            hits.append((r, ip))
            if progress:
                progress(f"发现设备: {r['name']} ({ip})")
    return hits

def discover_renderers(progress=None):
    """扫描局域网 DLNA 渲染设备, 返回 [{'name','ctrl','ip','model'}, ...]

    多级发现链, 不依赖任何固定端口:
      ① 候选主机(记忆IP/MAC定位IP)快速探测常见端口
      ② settings.json 里上次连接的完整控制地址
      ③ SSDP 组播搜索
      ④ 全网段常见端口扫描
      ⑤ 候选主机全端口深度扫描(终端兜底)
    """
    results, seen = [], set()

    def add(r, ip):
        if r and r["ctrl"] not in seen:
            seen.add(r["ctrl"])
            results.append(dict(r, ip=ip))
            if progress:
                progress(f"发现设备: {r['name']} ({ip})")
            return True
        return False

    # 候选主机 IP: 上次连接记录 + MAC 定位(应对 DHCP 换址), 数据来自本地 settings
    candidates = []
    last_settings = load_settings()
    m = re.match(r"http://([^:/]+)", last_settings.get("last_ctrl", ""))
    if m:
        candidates.append(m.group(1))
    mac_ip = _find_ip_by_mac(last_settings.get("mac", ""))
    if mac_ip and mac_ip not in candidates:
        candidates.append(mac_ip)
        if progress:
            progress(f"按设备网卡 MAC 定位到新 IP: {mac_ip}")

    if progress:
        progress("尝试已知设备 ...")
    online_candidates = []
    offline_candidates = []
    for ip in candidates:
        r, _port = _probe_host(ip, FAST_PORTS)
        if add(r, ip):
            online_candidates.append(ip)
        elif _ping_online(ip):
            online_candidates.append(ip)     # 在线但端口变了, 值得深度扫描
        else:
            offline_candidates.append(ip)
    if offline_candidates and progress:
        progress(f"上次的设备地址 {', '.join(offline_candidates)} 当前无响应")

    # 上次连接过的完整控制地址(含端口, 立即验证一次)
    last_ctrl = last_settings.get("last_ctrl", "")
    if last_ctrl:
        mm = re.match(r"(http://[^/]+)/", last_ctrl)
        if mm:
            base = mm.group(1)
            rr = _avtransport_from_desc(f"{base}/description.xml")
            add(rr, base.split("//")[1].split(":")[0])

    if progress:
        progress("SSDP 搜索局域网设备(约 5 秒) ...")
    for loc, ip in _ssdp_probe().items():
        add(_avtransport_from_desc(loc), ip)

    if not results:
        if progress:
            progress("常规发现未果, 扫描本网段常见端口(约 15 秒) ...")
        for r, ip in _subnet_scan(progress=progress):
            add(r, ip)

    if not results and online_candidates:
        # 终极兜底: 只对"像投影仪"的在线主机做全端口扫描
        # (对普通电脑/手机做全端口扫描既慢又无意义)
        for ip in online_candidates:
            hint = _projector_hint_ports(ip)
            if not hint:
                if progress:
                    progress(f"{ip} 无投影仪特征端口, 跳过深度扫描")
                continue
            if progress:
                progress(f"{ip} 有投影仪特征(端口 {hint}), 开始深度扫描 ...")
            for r, ip2 in _deep_port_scan(ip, progress):
                add(r, ip2)

    # 同一物理设备可能在多个端口提供相同服务(如自带 DLNA + 乐播同时开),
    # 或被多条发现路径命中 —— 控制地址不同但名字+IP 相同, 界面上就成了
    # 两条"一模一样"的记录。按 (IP, 名称) 折叠, 优先保留上次连接成功的那条。
    dedup = {}
    for r in results:
        key = (r["ip"], r["name"])
        if key not in dedup or r["ctrl"] == last_settings.get("last_ctrl"):
            dedup[key] = r
    results = list(dedup.values())

    if not results and progress:
        # 没找到设备: 给出可操作的诊断结论, 而不是干巴巴一句"未发现"
        progress("─" * 30)
        progress(f"诊断: 本机在 {_lan_prefix()}.x 网段, 扫描了整个网段未发现投屏设备——"
                 f"请核对投影仪「设置/网络」里显示的当前网络是否与电脑接的同一台路由器")
        if offline_candidates:
            progress(f"诊断: 上次连接的设备({', '.join(offline_candidates)})不在线"
                     f"(可能已改 IP 或已离线)")
        progress("正在检查网段内是否有'疑似投影仪'设备 ...")
        suspects = _find_suspects()
        if suspects:
            for ip, port in suspects:
                if port == 25826:
                    progress(f"诊断: {ip} 上发现 DLNA 服务但解析失败, 可尝试重启投影仪")
                else:
                    progress(f"诊断: {ip} 像是投影仪(端口 {port} 在线), "
                             f"但其投屏服务未开启——请在投影仪上打开「视频软件投屏」页面")
        else:
            progress("诊断: 网段内没有任何投影仪特征设备(已知设备与全子网均已排查)")

    if progress:
        progress(f"扫描完成, 共 {len(results)} 台设备" if results else "未发现可投屏设备")
    return results

# ---------------- SOAP 控制 ----------------

def soap(ctrl_url, action, body, timeout=8):
    payload = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        f"<s:Body>{body}</s:Body></s:Envelope>"
    ).encode()
    req = urllib.request.Request(ctrl_url, data=payload, method="POST", headers={
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPACTION": f'"urn:schemas-upnp-org:service:AVTransport:1#{action}"',
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode(errors="replace")

def cmd_body(action, inner):
    return (f'<u:{action} xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">'
            f"{inner}</u:{action}>")

# ---------------- 采集命令(跨平台) ----------------

def detect_windows_audio_device():
    """枚举 dshow 音频设备, 找立体声混音类设备; 找不到返回 None"""
    try:
        p = subprocess.run([FFMPEG, "-list_devices", "true", "-f", "dshow", "-i", "dummy"],
                           capture_output=True, timeout=10)
        text = (p.stderr or b"").decode(errors="replace")
    except Exception:
        return None
    keywords = ("stereo mix", "立体声混音", "virtual-audio-capturer", "what u hear")
    candidates = []
    for m in re.finditer(r'"([^"]+)"\s+\(audio\)', text, re.I):
        if any(k in m.group(1).lower() for k in keywords):
            candidates.append(m.group(1))
    return candidates[0] if candidates else None

def build_capture_cmd(mode, screen_size, audio_src, quality="hls", scale_height=0,
                      maxrate_cap="15M"):
    """构造屏幕采集 ffmpeg 命令; audio_src=None 表示纯画面。

    quality:
      "hls"  = CRF 自适应码率(B帧+自适应量化, 同码率更清晰) —— HLS 模式
      "live" = 恒定 CBR 10Mbps —— 裸流模式下部分渲染器(乐播)要求持续数据流
    scale_height: >0 时缩放输出高度(如 720 适配 720p 原生面板), 0=不缩放
    maxrate_cap: CRF 模式的码率上限(看门狗在网络差时自动调低)
    """
    color = ["-colorspace", "bt709", "-color_primaries", "bt709",
             "-color_trc", "bt709", "-color_range", "tv"]
    if quality == "hls":
        # 不用 zerolatency: HLS 分段播放对编码延迟不敏感, 关掉它换回
        # B帧+前向分析+自适应量化, 同码率下清晰度明显更好(实测满帧30fps)
        enc = ["-c:v", "libx264", "-preset", "veryfast",
               "-pix_fmt", "yuv420p",
               "-crf", "17", "-maxrate", maxrate_cap, "-bufsize", maxrate_cap,
               "-x264-params", "bframes=2:rc-lookahead=10:aq-mode=2",
               "-g", "30"] + color
    else:
        enc = ["-c:v", "libx264", "-preset", "veryfast", "-tune", "zerolatency",
               "-pix_fmt", "yuv420p",
               "-b:v", "10M", "-maxrate", "10M", "-bufsize", "10M",
               "-x264-params", "nal-hrd=cbr:force-cfr=1", "-g", "30"] + color
    if scale_height:
        # 让缩小用我们的高质量 lanczos, 而不是投影仪内置的低质量缩放器
        enc = ["-vf", f"scale=-2:{scale_height}:flags=lanczos"] + enc
    # 长时间投屏的音画同步保护: 采样点对齐视频时间戳, 防止漂移
    af = ["-af", "aresample=async=1"] if audio_src else []
    if IS_WIN:
        pre = ["-f", "gdigrab", "-framerate", "30", "-i", "desktop"]
        if audio_src:
            pre += ["-f", "dshow", "-i", f"audio={audio_src}"]
        else:
            pre += ["-an"]
        return [FFMPEG] + pre + enc + af + \
               (["-c:a", "aac", "-b:a", "128k", "-ar", "44100"]
                if audio_src else []) + \
               ["-f", "mpegts", "pipe:1"]
    # Linux
    pre = ["-f", "x11grab", "-draw_mouse", "1",
           "-video_size", screen_size, "-framerate", "30", "-i", ":0.0"]
    if audio_src == "fifo":
        pre += ["-f", "s16le", "-ar", "44100", "-ac", "2", "-i", AUDIO_FIFO]
        return [FFMPEG] + pre + enc + af + \
               ["-c:a", "aac", "-b:a", "128k", "-ar", "44100",
                "-f", "mpegts", "pipe:1"]
    return [FFMPEG] + pre + enc + ["-an", "-f", "mpegts", "pipe:1"]

# ---------------- 投屏引擎 ----------------

class CastEngine:
    """一次投屏会话: HTTP 服务 + 采集进程 + SOAP 控制"""

    def __init__(self, ctrl_url, log=print, model=""):
        self.ctrl_url = ctrl_url
        self.model = model
        self.log = log
        self.server = None
        self.port = PORT            # 实际绑定端口(8912 被占时会自动改用其他端口)
        self.ip = lan_ip_for(ctrl_url)   # 本机在"到设备网段"的地址(代理 TUN 不影响)
        self.procs = []            # [ffmpeg, parec, pacat, ...]
        self.procs_lock = threading.Lock()
        self.state = "空闲"
        self.sent_bytes = 0
        self.last_sent_print = 0
        # 滚动窗口(绝对序号追踪, 详见已验证的直推脚本)
        self.window = []
        self.window_base = 0
        self.window_lock = threading.Lock()
        self.MAX_WINDOW = int(3.5 * 1024 * 1024)
        self.TAIL_JOIN = int(1.5 * 1024 * 1024)
        self.file_mode = False
        self.hls_dir = None
        # 看门狗: 网络抖动导致播放器放弃拉流/编码器意外退出时自动恢复
        self._wd_active = threading.Event()
        self._last_size = None
        self._last_audio = None
        self._cap_mbps = 15      # CRF 码率上限(看门狗检测网络差时自动调低, 最低 6)
        self._full_repairs = 0   # 全量修复次数(用于码率阶梯)

    # --- 看门狗自愈 ---
    def _newest_segment_age(self):
        """最新切片的年龄(秒); 无切片返回大数"""
        newest = 0
        try:
            for f in os.listdir(self.hls_dir):
                if f.endswith(".ts"):
                    newest = max(newest, os.path.getmtime(os.path.join(self.hls_dir, f)))
        except OSError:
            return 1e9
        return max(0.0, time.time() - newest)

    def _watchdog(self):
        """每 5 秒体检一次:
        ① 编码器死亡/切片停更 → 整体重启采集并重新推送
        ② 切片在更新但播放器 >20 秒没拉数据 → 重新发 Play 踢一脚
        ③ 踢了两次还不拉 → 全量重新推送(SetAVTransportURI+Play)
        把'短暂卡顿后永久黑屏'变成 15~45 秒内自动恢复"""
        kicks = 0
        last_served, stall_rounds = 0, 0
        while self._wd_active.is_set():
            time.sleep(5)
            if not self._wd_active.is_set() or not self.hls_dir:
                continue
            enc_age = self._newest_segment_age()
            if enc_age > 8:
                # 编码器停更: 整体重启
                self.log(f"[看门狗] 切片已 {enc_age:.0f}s 未更新, 自动重启采集 ...")
                try:
                    self._stop_capture_procs()
                    self._run_hls_attempt(self._last_size, self._last_audio)
                    kicks, stall_rounds = 0, 0
                except Exception as e:
                    self.log(f"[看门狗] 重启失败: {e}")
                continue
            # 编码器正常, 检查播放器是否还在拉
            if self.sent_bytes != last_served:
                last_served, stall_rounds, kicks = self.sent_bytes, 0, 0
                continue
            stall_rounds += 1
            if stall_rounds >= 4:            # ~20 秒没拉数据
                kicks += 1
                if kicks <= 2:
                    self.log(f"[看门狗] 播放器 {stall_rounds*5}s 未拉流, 重新发 Play (第{kicks}次) ...")
                    try:
                        soap(self.ctrl_url, "Play",
                             cmd_body("Play", "<InstanceID>0</InstanceID><Speed>1</Speed>"),
                             timeout=15)
                    except Exception as e:
                        self.log(f"[看门狗] Play 失败: {e}")
                else:
                    # 踢了两轮无效: 全量重推; 若反复发生, 按阶梯调低码率上限
                    # (持续停拉多半是网络跟不上码率, 降码率换取连续性)
                    self._full_repairs += 1
                    if self._full_repairs % 2 == 0 and self._cap_mbps > 6:
                        self._cap_mbps = max(6, self._cap_mbps // 2)
                        self.log(f"[看门狗] 反复中断, 码率上限降至 {self._cap_mbps}Mbps 并重启采集 ...")
                        try:
                            self._stop_capture_procs()
                            self._run_hls_attempt(self._last_size, self._last_audio)
                            kicks = 0
                        except Exception as e:
                            self.log(f"[看门狗] 重启失败: {e}")
                    else:
                        self.log("[看门狗] 踢了两轮无效, 全量重新推送 ...")
                        try:
                            self._push(f"http://{self.ip}:{self.port}/hls/live.m3u8")
                            kicks = 0
                        except Exception as e:
                            self.log(f"[看门狗] 重推失败: {e}")
                stall_rounds = 0

    def _start_watchdog(self, screen_size, want_audio):
        self._last_size, self._last_audio = screen_size, want_audio
        self._wd_active.set()
        threading.Thread(target=self._watchdog, daemon=True).start()

    # --- HTTP 服务 ---
    def _make_handler(self):
        engine = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            # 关闭 Nagle 攒包: 切片响应立即发出, 消除 ~40ms 级微卡顿
            disable_nagle_algorithm = True

            def do_GET(self):
                self._route(send_body=True)

            def do_HEAD(self):
                # 部分渲染器(如投影仪自带的黄龙 DLNA)播放前会先发 HEAD 探测
                self._route(send_body=False)

            def _route(self, send_body):
                path = self.path.split("?")[0]
                if path.startswith("/hls/"):
                    engine._serve_hls(self, send_body, path)
                    return
                if path != "/stream.ts":
                    self.send_error(404)
                    return
                engine.log(f"设备 {self.client_address[0]} 前来拉流")
                if engine.file_mode:
                    engine._serve_file(self, send_body)
                else:
                    engine._serve_live(self, send_body)

            def log_message(self, *a):
                pass
        return Handler

    def _serve_file(self, http, send_body=True):
        size = os.path.getsize(STATIC_TS)
        rng = http.headers.get("Range")
        start, end = 0, size - 1
        if rng:
            m = re.match(r"bytes=(\d*)-(\d*)", rng)
            if m:
                if m.group(1):
                    start = int(m.group(1))
                if m.group(2):
                    end = min(int(m.group(2)), size - 1)
        length = end - start + 1
        http.send_response(206 if rng else 200)
        http.send_header("Content-Type", "video/mpeg")
        http.send_header("Content-Length", str(length))
        http.send_header("Accept-Ranges", "bytes")
        if rng:
            http.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        http.end_headers()
        if not send_body:
            return
        sent = 0
        try:
            with open(STATIC_TS, "rb") as f:
                f.seek(start)
                while sent < length:
                    chunk = f.read(min(1 << 18, length - sent))
                    if not chunk:
                        break
                    http.wfile.write(chunk)
                    sent += len(chunk)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass    # 渲染器探测后断开是正常行为
        self.sent_bytes += sent

    def _serve_live(self, http, send_body=True):
        http.send_response(200)
        http.send_header("Content-Type", "video/mpeg")
        http.send_header("transferMode.dlna.org", "Streaming")
        http.end_headers()
        if not send_body:
            http.close_connection = True
            return
        next_seq = None
        try:
            while True:
                with self.window_lock:
                    base = self.window_base
                    stop = base + len(self.window)
                    if next_seq is None:            # 首次接入: 回退约1秒, 从最近的流切入
                        acc, start_seq = 0, stop
                        for i in range(len(self.window) - 1, -1, -1):
                            acc += len(self.window[i])
                            start_seq = base + i
                            if acc >= self.TAIL_JOIN:
                                break
                        next_seq = start_seq
                    elif next_seq < base:
                        next_seq = base
                    data = b"".join(self.window[next_seq - base:stop - base])
                    next_seq = stop
                if data:
                    http.wfile.write(data)
                    self.sent_bytes += len(data)
                time.sleep(0.03)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _reader(self, proc):
        total = 0
        while True:
            chunk = proc.stdout.read(65536)
            if not chunk:
                break
            with self.window_lock:
                self.window.append(chunk)
                total += len(chunk)
                if total > self.MAX_WINDOW:
                    drop = total - self.MAX_WINDOW
                    i = 0
                    while drop > 0 and i < len(self.window):
                        n = len(self.window[i])
                        if n <= drop:
                            drop -= n
                            total -= n
                            i += 1
                        else:
                            self.window[i] = self.window[i][drop:]
                            total -= drop
                            drop = 0
                    del self.window[:i]
                    self.window_base += i

    # --- HLS 引擎(兼容不支持无限直播流的渲染器, 如投影仪自带黄龙 DLNA) ---
    def _hls_dir(self):
        return os.path.join(tempfile.gettempdir(), "cast_pig_hls")

    def _start_hls(self, screen_size, want_audio):
        """ffmpeg 直接输出 HLS 滚动切片; HTTP 侧以标准 HLS 提供,
        播放器轮询 live.m3u8 拉取新切片 —— 兼容性最好的直播方案"""
        d = self._hls_dir()
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d, exist_ok=True)
        self.hls_dir = d
        env = dict(os.environ)
        audio_arg = None
        if want_audio:
            if IS_WIN:
                audio_arg = detect_windows_audio_device()   # 无则自动纯画面
                if not audio_arg:
                    self.log("未找到立体声混音设备, 本次投屏无声音")
            else:
                audio_arg = "fifo"
                if os.path.exists(AUDIO_FIFO):
                    os.unlink(AUDIO_FIFO)
                os.mkfifo(AUDIO_FIFO)
                self._spawn(["bash", "-c",
                             f"exec parec --format=s16le --rate=44100 --channels=2 "
                             f"--file-format=raw > {AUDIO_FIFO}"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    self._spawn(["pacat", "-p", "--raw", "--format=s16le",
                                 "--rate=44100", "--channels=2", "/dev/zero"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except FileNotFoundError:
                    pass
                env["DISPLAY"] = ":0"
        cmd = build_capture_cmd(None, screen_size, audio_arg, quality="hls",
                                scale_height=int(load_settings().get("scale_height", 0) or 0),
                                maxrate_cap=f"{self._cap_mbps}M")
        # 把结尾的 raw TS 输出参数(最后一个 -f)替换为 HLS 封装
        # delete_threshold=4: 播放器网络短暂变慢时, 它来取的旧切片不会被立刻删掉
        # (默认只留 1 个, 易 404 导致播放器卡住重试) —— 抗卡顿的关键参数
        idx = len(cmd) - 1 - cmd[::-1].index("-f")
        cmd = cmd[:idx] + [
            "-f", "hls",
            "-hls_time", "1",
            "-hls_list_size", "8",
            "-hls_delete_threshold", "4",
            "-hls_flags", "delete_segments+omit_endlist+independent_segments",
            "-hls_segment_filename", os.path.join(d, "seg%05d.ts"),
            os.path.join(d, "live.m3u8"),
        ]
        p = self._spawn(cmd, stdout=subprocess.DEVNULL,
                        stderr=open("/tmp/cast_pig_ffmpeg.log", "ab"),
                        env=env)
        self.log("HLS 切片引擎已启动")
        return p

    def _serve_hls(self, http, send_body, path):
        """提供 HLS 播放列表与切片(HEAD/GET/Range 全支持)"""
        if not self.hls_dir:
            http.send_error(404)
            return
        fn = os.path.join(self.hls_dir, os.path.basename(path))
        if not os.path.isfile(fn):
            http.send_error(404)
            return
        mime = ("application/vnd.apple.mpegurl" if fn.endswith(".m3u8")
                else "video/mp2t")
        if fn.endswith(".m3u8"):
            with open(fn, "rb") as f:
                data = f.read()
            http.send_response(200)
            http.send_header("Content-Type", mime)
            http.send_header("Content-Length", str(len(data)))
            http.send_header("Cache-Control", "no-cache")
            http.send_header("Connection", "close")
            http.end_headers()
            if send_body:
                http.wfile.write(data)
            else:
                http.close_connection = True
            return
        size = os.path.getsize(fn)
        rng = http.headers.get("Range")
        start, end = 0, size - 1
        if rng:
            m = re.match(r"bytes=(\d*)-(\d*)", rng)
            if m:
                if m.group(1):
                    start = int(m.group(1))
                if m.group(2):
                    end = min(int(m.group(2)), size - 1)
        length = end - start + 1
        http.send_response(206 if rng else 200)
        http.send_header("Content-Type", mime)
        http.send_header("Content-Length", str(length))
        http.send_header("Accept-Ranges", "bytes")
        if rng:
            http.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        http.end_headers()
        if not send_body:
            http.close_connection = True
            return
        sent = 0
        try:
            with open(fn, "rb") as f:
                f.seek(start)
                while sent < length:
                    c = f.read(min(65536, length - sent))
                    if not c:
                        break
                    http.wfile.write(c)
                    sent += len(c)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        self.sent_bytes += sent

    # --- 采集启动 ---
    def _spawn(self, popen_args, **kw):
        p = subprocess.Popen(popen_args, **kw)
        with self.procs_lock:
            self.procs.append(p)
        return p

    def _start_capture(self, screen_size, want_audio):
        env = dict(os.environ)
        audio_src = None
        if want_audio:
            if IS_WIN:
                audio_src = detect_windows_audio_device()
                if audio_src:
                    self.log(f"使用系统声音: {audio_src}")
                else:
                    self.log("未找到立体声混音设备, 本次投屏无声音"
                             "(可在声音设置启用'立体声混音'后重试)")
            else:
                if os.path.exists(AUDIO_FIFO):
                    os.unlink(AUDIO_FIFO)
                os.mkfifo(AUDIO_FIFO)
                # parec 经 FIFO 喂给 ffmpeg(绕开 ffmpeg pulse 输入的性能坑)
                self._spawn(["bash", "-c",
                             f"exec parec --format=s16le --rate=44100 --channels=2 "
                             f"--file-format=raw > {AUDIO_FIFO}"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # 静音保活, 防止 monitor 声源挂起
                try:
                    self._spawn(["pacat", "-p", "--raw", "--format=s16le",
                                 "--rate=44100", "--channels=2", "/dev/zero"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except FileNotFoundError:
                    pass
                audio_src = "fifo"
                env["DISPLAY"] = ":0"
        # 裸流模式必须保持 CBR: 部分渲染器(乐播等)在码率暴跌时会断流
        p = self._spawn(build_capture_cmd(None, screen_size, audio_src, quality="live",
                                           scale_height=int(load_settings().get("scale_height", 0) or 0)),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, env=env, bufsize=10 ** 6)
        threading.Thread(target=self._reader, args=(p,), daemon=True).start()

    # --- 对外接口 ---
    def _bind_server(self):
        """启动 HTTP 服务; 8912 被占时先重试(等旧连接释放), 仍失败则自动换空闲端口"""
        last_err = None
        for _ in range(3):
            try:
                srv = _CastHTTPServer(("0.0.0.0", PORT), self._make_handler())
            except OSError as e:
                if getattr(e, "errno", None) != 98:
                    raise
                last_err = e
                time.sleep(0.8)
                continue
            self.server = srv
            self.port = srv.server_address[1]
            return
        # 端口持续被占用: 用系统分配的空闲端口, 不阻塞投屏
        srv = _CastHTTPServer(("0.0.0.0", 0), self._make_handler())
        self.server = srv
        self.port = srv.server_address[1]
        self.log(f"端口 {PORT} 被占用({last_err}), 已自动改用 {self.port}")

    def start_screen(self, screen_size, want_audio=True, hls=None):
        """hls: None=自动(按设备判定, 裸流不持续则自动切 HLS), True/False=强制"""
        auto = (hls is None)
        if hls is None:
            hls = self.needs_hls()
        self._bind_server()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self._wd_active.set()
        self._start_watchdog(screen_size, want_audio)
        if hls:
            self._run_hls_attempt(screen_size, want_audio)
            return
        ok = self._run_raw_attempt(screen_size, want_audio)
        if ok or not auto:
            return
        # 自动兜底: 设备没持续拉流(型号/端口未识别) → 换 HLS 兼容模式重试
        self.log("设备未持续拉流, 自动切换 HLS 兼容模式重试 ...")
        self._stop_capture_procs()
        self._run_hls_attempt(screen_size, want_audio)

    def _run_raw_attempt(self, screen_size, want_audio):
        """裸 TS 直播流(乐播等): CBR 恒码率下 sent_bytes 应持续增长"""
        self.file_mode = False
        self._start_capture(screen_size, want_audio)
        time.sleep(2.5)               # 预缓冲
        try:
            self._push(f"http://{self.ip}:{self.port}/stream.ts")
        except Exception as e:
            self.log(f"推送指令异常: {e}")
        start = time.time()
        last = self.sent_bytes
        last_change = time.time()
        while time.time() - start < 18:
            time.sleep(1)
            if self.sent_bytes != last:
                last = self.sent_bytes
                last_change = time.time()
            stall = time.time() - last_change
            if (self.sent_bytes > 2 * 1024 * 1024 and stall < 4
                    and time.time() - start > 8):
                self.state = "正在投屏(屏幕)"
                return True
        ok = self.sent_bytes > 2 * 1024 * 1024 and (time.time() - last_change) < 6
        if ok:
            self.state = "正在投屏(屏幕)"
        return ok

    def _run_hls_attempt(self, screen_size, want_audio):
        """HLS 滚动切片(黄龙等不接受无限直播流的渲染器)"""
        self._start_hls(screen_size, want_audio)
        # 等播放列表生成(ffmpeg 写出首个切片)
        for _ in range(60):
            time.sleep(0.5)
            if self.hls_dir and os.path.isfile(
                    os.path.join(self.hls_dir, "live.m3u8")):
                break
        self.file_mode = False
        try:
            self._push(f"http://{self.ip}:{self.port}/hls/live.m3u8")
        except Exception as e:
            self.log(f"推送指令异常: {e}")
        self.state = "正在投屏(HLS 屏幕)"

    def _stop_capture_procs(self):
        with self.procs_lock:
            for p in self.procs:
                if p.poll() is None:
                    try:
                        p.kill()
                    except OSError:
                        pass
            self.procs = []

    def needs_hls(self):
        """黄龙类渲染器(投影仪自带 DLNA, 25826)不接受无限直播流, 需要 HLS。
        判定不依赖端口: 同时认设备型号, 端口被改后依然正确"""
        blob = f"{self.ctrl_url} {self.model}".lower()
        return "25826" in blob or "huanglong" in blob or "黄龙" in self.model

    def start_file(self, path):
        self.file_mode = True
        subprocess.run([FFMPEG, "-y", "-i", path, "-c", "copy",
                        "-mpegts_flags", "+initial_discontinuity",
                        "-f", "mpegts", STATIC_TS],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        self._bind_server()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self._push(f"http://{self.ip}:{self.port}/stream.ts")
        self.state = "正在投屏(视频文件)"

    def _push(self, url):
        try:
            soap(self.ctrl_url, "Stop", cmd_body("Stop", "<InstanceID>0</InstanceID>"),
                 timeout=10)
        except Exception:
            pass
        if url.endswith(".m3u8"):
            # HLS 直播流: 实测黄龙等渲染器用空元数据最稳
            didl = None
        else:
            didl = ('<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" '
                    'xmlns:dc="http://purl.org/dc/elements/1.1/" '
                    'xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/">'
                    '<item id="1" parentID="0" restricted="1">'
                    "<dc:title>投屏猪</dc:title>"
                    "<upnp:class>object.item.videoItem</upnp:class>"
                    f'<res protocolInfo="http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_TS_SD_EU_ISO">'
                    f"{url}</res></item></DIDL-Lite>")
        # 兼容性两级尝试: 先按流类型给标准元数据(部分老渲染器靠它识别媒体类型),
        # 被拒绝(HTTPError 等)则退回空元数据(黄龙等同步实现设备实测最稳)
        variants = []
        if didl:
            variants.append(("标准元数据", escape(didl)))
        variants.append(("空元数据", ""))
        last_err = None
        for label, meta in variants:
            body = cmd_body("SetAVTransportURI",
                            "<InstanceID>0</InstanceID>"
                            f"<CurrentURI>{url}</CurrentURI>"
                            f"<CurrentURIMetaData>{meta}</CurrentURIMetaData>")
            try:
                # 黄龙等渲染器的 SetAVTransportURI 是同步实现, 可能等待约10秒才响应
                soap(self.ctrl_url, "SetAVTransportURI", body, timeout=28)
                soap(self.ctrl_url, "Play",
                     cmd_body("Play", "<InstanceID>0</InstanceID><Speed>1</Speed>"),
                     timeout=20)
                self.log(f"已发送播放指令({label})")
                return
            except Exception as e:
                last_err = e
                self.log(f"{label}被拒绝({e}), 尝试下一种格式 ...")
        self.log(f"推送失败: {last_err}")

    def stop(self):
        self._wd_active.clear()      # 先停看门狗, 避免它干扰清理过程
        try:
            soap(self.ctrl_url, "Stop", cmd_body("Stop", "<InstanceID>0</InstanceID>"),
                 timeout=5)
        except Exception:
            pass
        with self.procs_lock:
            for p in self.procs:
                if p.poll() is None:
                    try:
                        p.kill()
                    except OSError:
                        pass
            self.procs = []
        if self.server:
            srv = self.server
            self.server = None
            # shutdown() 只是停止循环, 必须再 server_close() 才能真正释放监听端口
            def _close(srv=srv):
                try:
                    srv.shutdown()
                except Exception:
                    pass
                try:
                    srv.server_close()
                except Exception:
                    pass
            threading.Thread(target=_close, daemon=True).start()
        self.state = "已停止"
        for f in (AUDIO_FIFO,):
            try:
                if os.path.exists(f):
                    os.unlink(f)
            except OSError:
                pass
        if self.hls_dir and os.path.isdir(self.hls_dir):
            shutil.rmtree(self.hls_dir, ignore_errors=True)

def my_ip(target_hint=None):
    """探测本机在目标设备网段的 IP。

    按"到目标设备的路由"选择本机地址, 而不是连 8.8.8.8——后者在开启代理
    TUN/虚拟网卡时会把 IP 猜成虚拟地址(如 198.18.0.1), 设备根本访问不到。
    """
    def _probe(host):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((host, 80))
            return s.getsockname()[0]
        finally:
            s.close()
    if target_hint:
        try:
            return _probe(target_hint)
        except OSError:
            pass
    try:
        return _probe("8.8.8.8")
    except OSError:
        return "127.0.0.1"

def lan_ip_for(ctrl_url):
    """从设备控制地址解析出设备 IP, 用于按路由探测本机地址"""
    m = re.match(r"https?://([^:/]+)", ctrl_url or "")
    return my_ip(m.group(1) if m else None)

# ---------------- 图形界面 ----------------

_single_lock = [None]

def _acquire_single_instance():
    """单实例锁: 已有窗口在运行时返回 False, 防止双击开两份互相抢设备/端口。
    Linux 用 flock(进程退出自动释放); Windows 跳过此检查(端口兜底已足够)"""
    if IS_WIN:
        return True
    try:
        import fcntl
        f = open(os.path.join(tempfile.gettempdir(), "cast_pig.lock"), "w")
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _single_lock[0] = f      # 持有到进程结束
        return True
    except OSError:
        return False

def run_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog

    if not _acquire_single_instance():
        try:
            r = tk.Tk()
            r.withdraw()
            from tkinter import messagebox
            messagebox.showinfo("投屏猪", "投屏猪已经在运行了，请使用已打开的窗口。")
            r.destroy()
        except Exception:
            print("[投屏猪] 已在运行, 本次退出")
        return

    root = tk.Tk()
    root.title(f"投屏猪 v{VERSION} · 绿色版")
    root.geometry("520x420")
    root.minsize(480, 380)

    style = ttk.Style()
    if "clam" in style.theme_names():
        style.theme_use("clam")

    devices = []          # [(名称, 控制地址, IP)]
    engine_box = [None]
    casting = [False]
    busy = [False]        # 连接进行中(防止重复点击并发抢端口)
    auto_tried = [False]

    top = ttk.Frame(root, padding=10)
    top.pack(fill="x")
    ttk.Button(top, text="⟳ 扫描设备", command=lambda: refresh()).pack(side="left")
    ttk.Button(top, text="手动输入IP", command=lambda: add_manual_ip()).pack(side="left", padx=(6, 0))
    status_var = tk.StringVar(value="点击「扫描设备」开始")
    ttk.Label(top, textvariable=status_var).pack(side="left", padx=12)

    list_box = tk.Listbox(root, height=8, font=("", 11), activestyle="dotbox")
    list_box.pack(fill="both", expand=True, padx=10, pady=(0, 8))

    # 扫描失败时显示的可操作诊断(常驻, 不随状态栏刷新消失)
    diag_var = tk.StringVar(value="")
    diag_label = tk.Label(root, textvariable=diag_var, justify="left", anchor="w",
                          fg="#a33", bg="#fff4f4", wraplength=480, padx=8, pady=6)
    # 只在有内容时显示(由 _scan 控制 pack/pack_forget)

    mode_frame = ttk.LabelFrame(root, text="投屏内容", padding=8)
    mode_frame.pack(fill="x", padx=10)
    mode_var = tk.StringVar(value="screen")
    file_path = tk.StringVar()

    def pick_file():
        p = filedialog.askopenfilename(title="选择要投屏的视频",
                                       filetypes=[("视频文件", "*.mp4 *.mkv *.avi *.mov *.ts *.flv *.webm"),
                                                  ("所有文件", "*.*")])
        if p:
            file_path.set(p)
            mode_var.set("file")
            update_mode()

    def update_mode():
        if mode_var.get() == "file":
            file_label.configure(text=file_path.get() or "(未选择文件)")

    ttk.Radiobutton(mode_frame, text="屏幕 + 系统声音", value="screen",
                    variable=mode_var, command=update_mode).pack(side="left")
    ttk.Radiobutton(mode_frame, text="仅屏幕画面", value="screen-quiet",
                    variable=mode_var, command=update_mode).pack(side="left")
    ttk.Radiobutton(mode_frame, text="视频文件(无损+声音)", value="file",
                    variable=mode_var, command=update_mode).pack(side="left")
    ttk.Button(mode_frame, text="选择文件…", command=pick_file).pack(side="left", padx=6)
    file_label = ttk.Label(mode_frame, textvariable=file_path, foreground="#086")
    file_label.pack(side="left")

    # 输出分辨率(屏幕镜像模式): 投影仪面板为 720p 时选 720p 更清晰
    res_frame = ttk.Frame(root, padding=(10, 0, 10, 4))
    res_frame.pack(fill="x")
    ttk.Label(res_frame, text="输出画质:").pack(side="left")
    res_var = tk.StringVar(value="原始分辨率 (推荐)")
    res_map = {"原始分辨率 (推荐)": 0,
               "1280x720 (投影仪是720p面板时更清晰)": 720,
               "1920x1080": 1080}
    res_combo = ttk.Combobox(res_frame, textvariable=res_var, state="readonly",
                             values=list(res_map.keys()), width=38)
    res_combo.pack(side="left", padx=(6, 0))
    last_scale = int(load_settings().get("scale_height", 0) or 0)
    for label, h in res_map.items():
        if h == last_scale:
            res_var.set(label)
            break

    btn_frame = ttk.Frame(root, padding=10)
    btn_frame.pack(fill="x")
    start_btn = ttk.Button(btn_frame, text="▶  开始投屏", command=lambda: start_cast())
    start_btn.pack(side="left")
    stop_btn = ttk.Button(btn_frame, text="■  停止", command=lambda: stop_cast(),
                          state="disabled")
    stop_btn.pack(side="left", padx=8)
    info_var = tk.StringVar(value="")
    ttk.Label(root, textvariable=info_var, foreground="#555",
              padding=10).pack(fill="x")

    def log(msg):
        status_var.set(f"{msg}")
        print(f"[投屏猪] {msg}")

    def refresh():
        list_box.delete(0, "end")
        start_btn.configure(state="disabled")
        diag_var.set("")
        diag_label.pack_forget()
        threading.Thread(target=_scan, daemon=True).start()

    def _scan():
        log("扫描中 …")
        diag_lines = []

        def note(msg):
            # 诊断类消息(以"诊断:"/"上次的设备"开头)同时收集, 供常驻展示
            if msg.startswith(("诊断", "上次的设备")):
                diag_lines.append(msg.replace("诊断: ", ""))
            log(msg)

        found = discover_renderers(progress=lambda m: root.after(0, note, m))

        def apply():
            devices.clear()
            devices.extend(found)
            for dev in devices:
                list_box.insert("end", f"  {dev['name']}   ({dev['ip']})")
            if devices:
                list_box.selection_set(0)
                list_box.activate(0)
                start_btn.configure(state="normal")
            else:
                # 没找到设备: 常驻显示原因 + 弹窗, 避免用户以为程序卡住了
                text = "\n".join(dict.fromkeys(diag_lines)) or "未发现可投屏设备"
                tip = ("\n\n常见原因: 投影仪未开机 / 未连接同一路由器 / "
                       "或在投影仪上开了「安卓镜像(WiFi直连)」——该模式会断开它与路由器的连接，"
                       "请退出回首页后再试")
                diag_var.set(text + tip)
                diag_label.pack(fill="x", padx=10, pady=(0, 6),
                               before=mode_frame)
            auto_select()
        root.after(0, apply)

    def auto_select():
        """打开后: 在列表里预选中上次用过的设备并恢复上次模式(不自动投屏)"""
        if auto_tried[0] or not devices:
            return
        auto_tried[0] = True
        last = load_settings()
        ctrl = last.get("last_ctrl")
        found_last = False
        found_name = ""
        if ctrl:
            for i, dev in enumerate(devices):
                if dev["ctrl"] == ctrl:
                    mode = last.get("mode", "screen")
                    if mode == "file" and not os.path.isfile(last.get("file", "")):
                        mode = "screen"
                    mode_var.set(mode)
                    if mode == "file":
                        file_path.set(last.get("file", ""))
                    list_box.selection_clear(0, "end")
                    list_box.selection_set(i)
                    list_box.activate(i)
                    list_box.see(i)
                    found_last = True
                    found_name = dev["name"]
                    break
        if found_last:
            if len(devices) > 1:
                log(f"已预选上次的设备「{found_name}」；"
                    f"共 {len(devices)} 台设备，可另行选择，然后点「开始投屏」")
            else:
                log(f"已找到设备「{found_name}」，点「开始投屏」即投")
        else:
            log("发现设备，请选择后点「开始投屏」")

    def add_manual_ip():
        """手动输入设备 IP 连接: 自动发现失灵时的兜底通道。
        先快速探测常见端口, 失败则对该 IP 做全端口深度扫描"""
        import tkinter.simpledialog as sd
        ip = sd.askstring(
            "手动连接设备",
            "输入设备的 IP 地址\n\n(投影仪上: 设置 → 网络设置 里可查看当前 IP)",
            parent=root)
        if not ip:
            return
        ip = ip.strip()
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            log("IP 格式不正确, 应类似 192.168.1.17")
            return
        log(f"正在探测 {ip} 的投屏服务 ...")
        busy[0] = True
        start_btn.configure(state="disabled")

        def _add(r, found_ip):
            if any(d["ctrl"] == r["ctrl"] for d in devices):
                # 已在列表里, 选中即可
                for i, d in enumerate(devices):
                    if d["ctrl"] == r["ctrl"]:
                        idx = i
                        break
            else:
                devices.append(dict(r, ip=found_ip))
                list_box.insert("end", f"  {r['name']}   ({found_ip})")
                idx = len(devices) - 1
            list_box.selection_clear(0, "end")
            list_box.selection_set(idx)
            list_box.activate(idx)
            list_box.see(idx)
            start_btn.configure(state="normal")
            log(f"已添加设备「{r['name']}」({found_ip})，点「开始投屏」即投")

        def work():
            r, _port = _probe_host(ip, FAST_PORTS)
            if not r:
                root.after(0, log, f"{ip} 常见端口未找到, 开始全端口深度扫描(约 15 秒) ...")
                for rr, ip2 in _deep_port_scan(ip, lambda m: root.after(0, log, m)):
                    r = rr
                    break
            def apply():
                nonlocal r
                if r:
                    _add(r, ip)
                    diag_var.set("")
                    diag_label.pack_forget()
                else:
                    log(f"{ip} 上未找到投屏服务。请核对: ① IP 是否正确(投影仪 设置→网络 可查) "
                        f"② 投影仪与电脑是否连接同一台路由器 ③ 投影仪是否停在「安卓镜像」页面")
                    diag_var.set(f"手动添加 {ip} 失败: 该地址上没有投屏服务。\n"
                                 f"请核对投影仪 设置→网络 里显示的 IP 和 WiFi 名称——"
                                 f"它必须与电脑连接同一台路由器(如 ChinaNet-SP6a)。")
                    diag_label.pack(fill="x", padx=10, pady=(0, 6),
                                   before=mode_frame)
                busy[0] = False
            root.after(0, apply)

        threading.Thread(target=work, daemon=True).start()

    def start_cast():
        if busy[0]:
            log("正在连接中, 请稍候 …(投屏进行中不要重复点击)")
            return
        sel = list_box.curselection()
        if not sel:
            log("请先在列表中选择一台设备")
            return
        if mode_var.get() == "file" and not file_path.get():
            log("请先选择视频文件")
            return
        busy[0] = True
        start_btn.configure(state="disabled")   # 连接期间禁用按钮, 防止并发抢端口
        dev = devices[sel[0]]
        log(f"连接 {dev['name']} …(首次连接约需 10 秒)")
        threading.Thread(target=_cast, args=(dev,), daemon=True).start()

    def _cast(dev):
        try:
            eng = CastEngine(dev["ctrl"], log=lambda m: root.after(0, log, m),
                             model=dev.get("model", ""))
            engine_box[0] = eng
            if mode_var.get() == "file":
                eng.start_file(file_path.get())
            else:
                w, h = root.winfo_screenwidth(), root.winfo_screenheight()
                eng.start_screen(f"{w}x{h}", want_audio=(mode_var.get() == "screen"))
            casting[0] = True
            save_settings({"last_ctrl": dev["ctrl"], "name": dev["name"],
                           "mac": _mac_of_ip(dev.get("ip", ""))
                                  or load_settings().get("mac", ""),
                           "mode": mode_var.get(),
                           "scale_height": res_map.get(res_var.get(), 0),
                           "file": file_path.get() if mode_var.get() == "file" else ""})
            root.after(0, lambda: (start_btn.configure(state="disabled"),
                                   stop_btn.configure(state="normal")))
        except OSError as e:
            if getattr(e, "errno", None) == 98:
                root.after(0, log, "端口被占用: 可能有另一个投屏猪窗口在运行, "
                                   "请关掉旧窗口后重试")
            else:
                root.after(0, log, f"投屏失败: {e}")
        except Exception as e:
            root.after(0, log, f"投屏失败: {e}")
        finally:
            busy[0] = False
            if not casting[0]:
                root.after(0, lambda: start_btn.configure(state="normal"))

    def stop_cast():
        eng = engine_box[0]
        if eng:
            threading.Thread(target=eng.stop, daemon=True).start()
        casting[0] = False
        start_btn.configure(state="normal")
        stop_btn.configure(state="disabled")
        log("已停止")

    def _tick():
        eng = engine_box[0]
        if eng and casting[0]:
            info_var.set(f"{eng.state} · 已发送 {eng.sent_bytes/1e6:.1f} MB")
        root.after(1000, _tick)
    _tick()

    def on_close():
        eng = engine_box[0]
        if eng:
            try:
                eng.stop()      # 同步停止, 确保发送 Stop 指令并清理进程
            except Exception:
                pass
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    refresh()          # 打开即自动扫描
    root.mainloop()

def selftest():
    """无界面自检: 发现设备 → 投屏(自动选模式) → 停止"""
    print("[自检] 设备发现 ...")
    devs = discover_renderers()
    if not devs:
        print("[自检] 未发现设备!")
        return 1
    for dev in devs:
        print(f"  - {dev['name']} ({dev['ip']}) model={dev.get('model','?')}")
        print(f"    ctrl={dev['ctrl']}")
    dev = devs[0]
    is_hls = "25826" in dev["ctrl"] or "huanglong" in dev.get("model", "").lower()
    print(f"[自检] 向 {dev['name']} 投屏 10 秒 (HLS={is_hls}) ...")
    eng = CastEngine(dev["ctrl"], model=dev.get("model", ""))
    eng.start_screen("1920x1080", want_audio=True)
    prev = 0
    for _ in range(10):
        time.sleep(1)
        if eng.sent_bytes != prev:
            print(f"  已发送 {eng.sent_bytes/1e6:.1f} MB")
            prev = eng.sent_bytes
    eng.stop()
    print(f"[自检] 完成 ✓ 总发送 {eng.sent_bytes/1e6:.1f} MB")
    return 0

if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    run_gui()
