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
        with urllib.request.urlopen(desc_url, timeout=4) as r:
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
    """快速探测某主机上第一个可用的 DLNA 服务"""
    for port in ports:
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

def _subnet_scan(ports=(25826, 49152, 49153, 49154), progress=None):
    """并发扫描本网段, 找支持 DLNA 的设备(用于不响应 SSDP 的型号)"""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    prefix = ".".join(my_ip().split(".")[:3])
    hits = []

    def probe(i):
        return _probe_host(f"{prefix}.{i}", ports)

    with ThreadPoolExecutor(max_workers=128) as ex:
        futs = {ex.submit(probe, i): i for i in range(1, 255)}
        for fut in as_completed(futs):
            try:
                r, port = fut.result()
            except Exception:
                continue
            if r:
                hits.append((r, f"{prefix}.{futs[fut]}"))
                if progress:
                    progress(f"发现设备: {r['name']} ({prefix}.{futs[fut]})")
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
    for ip in candidates:
        r, _port = _probe_host(ip, FAST_PORTS)
        add(r, ip)

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

    if not results:
        # 终极兜底: 候选主机全端口扫描, 渲染器端口改成什么都能找到
        for ip in candidates:
            for r, ip2 in _deep_port_scan(ip, progress):
                add(r, ip2)

    if progress:
        progress(f"扫描完成, 共 {len(results)} 台设备" if results else "未发现任何设备")
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

def build_capture_cmd(mode, screen_size, audio_src):
    """构造屏幕采集 ffmpeg 命令; audio_src=None 表示纯画面"""
    enc = ["-c:v", "libx264", "-preset", "veryfast", "-tune", "zerolatency",
           "-pix_fmt", "yuv420p",
           "-b:v", "10M", "-maxrate", "10M", "-bufsize", "10M",
           "-x264-params", "nal-hrd=cbr:force-cfr=1", "-g", "30"]
    if IS_WIN:
        pre = ["-f", "gdigrab", "-framerate", "30", "-i", "desktop"]
        if audio_src:
            pre += ["-f", "dshow", "-i", f"audio={audio_src}"]
        else:
            pre += ["-an"]
        return [FFMPEG] + pre + enc + (["-c:a", "aac", "-b:a", "128k", "-ar", "44100"]
                                       if audio_src else []) + \
               ["-f", "mpegts", "pipe:1"]
    # Linux
    pre = ["-f", "x11grab", "-draw_mouse", "1",
           "-video_size", screen_size, "-framerate", "30", "-i", ":0.0"]
    if audio_src == "fifo":
        pre += ["-f", "s16le", "-ar", "44100", "-ac", "2", "-i", AUDIO_FIFO]
        return [FFMPEG] + pre + enc + \
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

    # --- HTTP 服务 ---
    def _make_handler(self):
        engine = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

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
        cmd = build_capture_cmd(None, screen_size, audio_arg)
        # 把结尾的 raw TS 输出参数(最后一个 -f)替换为 HLS 封装
        idx = len(cmd) - 1 - cmd[::-1].index("-f")
        cmd = cmd[:idx] + [
            "-f", "hls",
            "-hls_time", "1",
            "-hls_list_size", "6",
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
        p = self._spawn(build_capture_cmd(None, screen_size, audio_src),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, env=env, bufsize=10 ** 6)
        threading.Thread(target=self._reader, args=(p,), daemon=True).start()

    # --- 对外接口 ---
    def start_screen(self, screen_size, want_audio=True, hls=None):
        """hls: None=自动(按设备判定, 裸流不持续则自动切 HLS), True/False=强制"""
        auto = (hls is None)
        if hls is None:
            hls = self.needs_hls()
        self.server = ThreadingHTTPServer(("0.0.0.0", PORT), self._make_handler())
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
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
            self._push(f"http://{my_ip()}:{PORT}/stream.ts")
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
            self._push(f"http://{my_ip()}:{PORT}/hls/live.m3u8")
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
        self.server = ThreadingHTTPServer(("0.0.0.0", PORT), self._make_handler())
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self._push(f"http://{my_ip()}:{PORT}/stream.ts")
        self.state = "正在投屏(视频文件)"

    def _push(self, url):
        try:
            soap(self.ctrl_url, "Stop", cmd_body("Stop", "<InstanceID>0</InstanceID>"),
                 timeout=10)
        except Exception:
            pass
        if url.endswith(".m3u8"):
            # HLS 直播流: 实测黄龙等渲染器用空元数据最稳
            meta = ""
        else:
            didl = ('<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" '
                    'xmlns:dc="http://purl.org/dc/elements/1.1/" '
                    'xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/">'
                    '<item id="1" parentID="0" restricted="1">'
                    "<dc:title>投屏猪</dc:title>"
                    "<upnp:class>object.item.videoItem</upnp:class>"
                    f'<res protocolInfo="http-get:*:video/mpeg:DLNA.ORG_PN=MPEG_TS_SD_EU_ISO">'
                    f"{url}</res></item></DIDL-Lite>")
            meta = escape(didl)
        body = cmd_body("SetAVTransportURI",
                        "<InstanceID>0</InstanceID>"
                        f"<CurrentURI>{url}</CurrentURI>"
                        f"<CurrentURIMetaData>{meta}</CurrentURIMetaData>")
        # 黄龙等渲染器的 SetAVTransportURI 是同步实现, 可能等待约10秒才响应
        soap(self.ctrl_url, "SetAVTransportURI", body, timeout=28)
        soap(self.ctrl_url, "Play",
             cmd_body("Play", "<InstanceID>0</InstanceID><Speed>1</Speed>"), timeout=20)
        self.log("已发送播放指令")

    def stop(self):
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
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            self.server = None
        self.state = "已停止"
        for f in (AUDIO_FIFO,):
            try:
                if os.path.exists(f):
                    os.unlink(f)
            except OSError:
                pass
        if self.hls_dir and os.path.isdir(self.hls_dir):
            shutil.rmtree(self.hls_dir, ignore_errors=True)

def my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"

# ---------------- 图形界面 ----------------

def run_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog

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
    auto_tried = [False]

    top = ttk.Frame(root, padding=10)
    top.pack(fill="x")
    ttk.Button(top, text="⟳ 扫描设备", command=lambda: refresh()).pack(side="left")
    status_var = tk.StringVar(value="点击「扫描设备」开始")
    ttk.Label(top, textvariable=status_var).pack(side="left", padx=12)

    list_box = tk.Listbox(root, height=8, font=("", 11), activestyle="dotbox")
    list_box.pack(fill="both", expand=True, padx=10, pady=(0, 8))

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
        threading.Thread(target=_scan, daemon=True).start()

    def _scan():
        log("扫描中 …")
        found = discover_renderers(progress=lambda m: root.after(0, log, m))
        def apply():
            devices.clear()
            devices.extend(found)
            for dev in devices:
                list_box.insert("end", f"  {dev['name']}   ({dev['ip']})")
            if devices:
                list_box.selection_set(0)
                list_box.activate(0)
                start_btn.configure(state="normal")
            auto_connect()
        root.after(0, apply)

    def auto_connect():
        """打开即投: 上次用过的设备在列表里 → 自动开始(仅首次扫描尝试)"""
        if auto_tried[0] or casting[0] or not devices:
            return
        auto_tried[0] = True
        last = load_settings()
        ctrl = last.get("last_ctrl")
        if not ctrl:
            return
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
                log(f"自动连接上次的设备: {dev['name']}")
                start_cast()
                return

    def start_cast():
        sel = list_box.curselection()
        if not sel:
            log("请先在列表中选择一台设备")
            return
        if mode_var.get() == "file" and not file_path.get():
            log("请先选择视频文件")
            return
        dev = devices[sel[0]]
        log(f"连接 {dev['name']} …")
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
                           "file": file_path.get() if mode_var.get() == "file" else ""})
            root.after(0, lambda: (start_btn.configure(state="disabled"),
                                   stop_btn.configure(state="normal")))
        except Exception as e:
            root.after(0, log, f"投屏失败: {e}")

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
