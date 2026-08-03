#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare 可用节点两段式探测脚本
=================================

判断某个 IP:端口 是否可用的逻辑（两批探测）：

  第一批 · TLS 探测：
      对每个 IP:端口 建立 TCP 连接并完成 TLS 握手（SNI: www.cloudflare.com），
      校验对端返回的服务器证书包含 www.cloudflare.com（CN 或 SAN 任一命中即可）。
      证书命中者保留，进入第二批。

  第二批 · HTTP 探测：
      对第一批保留的节点发起 HTTP(S) GET / 请求，
      请求头 Host: crypto.cloudflare.com（SNI 同主机名），
      响应状态码为 301 的节点判定为可用，写入结果文件。

  “第一批保留 → 第二批 301 通过”= 该 IP:端口 可用。

仅依赖 Python 标准库，无需安装第三方包，可直接在 GitHub Actions 中运行。

用法示例：
  # 1) 从候选文件探测（每行 ip 或 ip:port，# 开头为注释）
  python cloudflare_probe.py --input nodes.txt

  # 2) 自动从 Cloudflare 官方 IP 段采样候选并探测
  python cloudflare_probe.py --generate 2000 --ports 443,2053,2083 --workers 200

  # 3) 完整参数
  python cloudflare_probe.py --input nodes.txt --port 443 \
      --out usable_nodes.txt --report probe_report.txt \
      --workers 200 --timeout 5 \
      --probe-host crypto.cloudflare.com --expect-code 301 --scheme https
"""

import argparse
import concurrent.futures
import os
import random
import re
import socket
import ssl
import urllib.request

# 第一批：证书需命中该域名
CERT_MARK = "www.cloudflare.com"
# 第二批：HTTP 请求使用的 Host / SNI
DEFAULT_PROBE_HOST = "crypto.cloudflare.com"
DEFAULT_EXPECT_CODE = 301
DEFAULT_PORTS = [443]
UA = "Mozilla/5.0 (compatible; cloudflare-node-probe/1.0)"

# 全局 TLS 上下文：不做主机名校验与证书信任校验（我们要的就是“看一眼证书”）
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE


def ensure_dir(path: str) -> None:
    """确保输出文件的父目录存在（不存在则创建）。"""
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)


def cert_names(der: bytes) -> list:
    """从 DER 证书中提取 CN 与 DNS SAN 列表（仅标准库实现）。"""
    mark = CERT_MARK.encode("ascii")
    names = []
    try:
        # CPython 内部解码接口，广泛用于自管理证书检查
        cert = ssl._ssl._test_decode_cert(der)
        for rdn in cert.get("subject", ()):
            for key, val in rdn:
                if key == "commonName":
                    names.append(val)
        for san in cert.get("subjectAltName", ()):
            for typ, val in san:
                if typ == "DNS":
                    names.append(val)
    except Exception:
        # 部分证书字段含嵌入 NUL 字节，_test_decode_cert 会抛 ValueError。
        # 兜底：在原始 DER 中按字节匹配域名（SAN/CN 以 IA5/UTF8String 明文存储）。
        pass
    # 无论结构化解析成败，都再用字节直接匹配一次，避免漏判
    if isinstance(der, bytes) and mark in der and (not names or CERT_MARK not in names):
        names.append(CERT_MARK)
    # 去重保序
    return list(dict.fromkeys(n for n in names if n))


def tls_probe(ip: str, port: int, timeout: float):
    """第一批：TLS 探测，返回 (是否通过, 说明)。"""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        s = ssl_ctx.wrap_socket(sock, server_hostname=CERT_MARK)
        der = s.getpeercert(binary_form=True)
        s.close()
        sock = None
    except Exception as exc:
        return False, "tls:%s" % exc.__class__.__name__
    names = cert_names(der or b"")
    if not names:
        return False, "tls:no-cert"
    ok = any(CERT_MARK in n for n in names)
    return ok, "cert:%s" % "|".join(names[:5])


def http_probe(ip: str, port: int, timeout: float,
               host: str, expected: int, scheme: str):
    """第二批：HTTP(S) 请求 Host: crypto.cloudflare.com，期望 301。"""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        s = sock
        if scheme == "https":
            s = ssl_ctx.wrap_socket(sock, server_hostname=host)
        s.settimeout(timeout)
        req = (
            "GET / HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Connection: close\r\n\r\n" % (host, UA)
        )
        s.sendall(req.encode("ascii"))
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:  # 拿到响应头即可
                break
        s.close()
        sock = None
    except Exception as exc:
        return False, "http:%s" % exc.__class__.__name__

    head = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = head.split(" ", 2)
    code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    loc = ""
    for ln in data.split(b"\r\n"):
        if ln.lower().startswith(b"location:"):
            loc = ln.split(b":", 1)[1].decode("latin-1", "replace").strip()
            break
    return code == expected, "http:%d %s" % (code, loc[:60])


def parse_node(line: str, default_port: int):
    """解析一行候选：`ip`、`ip:port` 或 `[ipv6]:port`。

    兼容形如 `ip:port#KR(56.08Mbps,...)` 的列表格式：
    `#` 之后的内容一律视为注释/附加信息被丢弃。
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    line = line.split("#", 1)[0].strip()  # 去掉 # 后的附加信息
    if not line:
        return None
    if line.startswith("["):  # IPv6: [addr]:port 或 [addr]
        m = re.match(r"^\[([0-9a-fA-F:]+)\](?::(\d+))?$", line)
        if m:
            return m.group(1), int(m.group(2) or default_port)
        return None
    if ":" in line:
        ip, _, port = line.rpartition(":")
        if port.isdigit() and ip:
            return ip, int(port)
        return None  # 无端口的裸 IPv6 请用 [addr]
    return line, default_port


def load_nodes(path: str, default_port: int):
    nodes = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            n = parse_node(line, default_port)
            if n:
                nodes.append(n)
    return nodes


def ip2int(ip: str) -> int:
    a, b, c, d = map(int, ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def int2ip(x: int) -> str:
    return ".".join(str((x >> s) & 255) for s in (24, 16, 8, 0))


def sample_from_cidr(cidr: str, rng: random.Random):
    """在一个 CIDR 内采样少量 IP（/24 以下按 /24 粒度、每个 /24 取 1 个随机主机位）。"""
    net, bits_s = cidr.split("/")
    bits = int(bits_s)
    base = ip2int(net)
    if bits >= 32:
        return [net]
    if bits <= 24:
        n24 = 1 << (24 - bits)
        return [int2ip(base + (i << 8) + rng.randrange(1, 255)) for i in range(n24)]
    size = 1 << (32 - bits)
    if size <= 2:
        return [int2ip(base + 1)]
    return [int2ip(base + rng.randrange(1, size - 1))]


def generate_nodes(max_nodes: int, ports: list, timeout: float):
    """从 Cloudflare 官方 IPv4 段采样候选节点，返回 (nodes, cidrs)。"""
    url = "https://www.cloudflare.com/ips-v4"
    print("[*] 拉取 Cloudflare 官方 IPv4 段: %s" % url)
    with urllib.request.urlopen(url, timeout=timeout) as r:
        cidrs = [l.strip() for l in r.read().decode().splitlines() if l.strip()]
    rng = random.Random()
    ips = []
    for c in cidrs:
        ips.extend(sample_from_cidr(c, rng))
    ips = sorted(set(ips))
    rng.shuffle(ips)
    per_port = max(max_nodes // max(len(ports), 1), 1)
    ips = ips[:per_port]
    nodes = [(ip, port) for ip in ips for port in ports]
    return nodes, cidrs


def split_nodes(text: str) -> list:
    """把逗号/换行分隔的节点串拆成单个地址。

    与 parse_node 配套：`#...` 注释里（括号内）的逗号不计为分隔符，
    例如 `ip1:port1#KR(a=1,b=2),ip2:port2` 只会拆成两段。
    """
    out, cur, depth = [], "", 0
    for ch in text.replace("\n", ","):
        if ch == "," and depth == 0:
            if cur.strip():
                out.append(cur)
            cur = ""
        else:
            cur += ch
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(depth - 1, 0)
    if cur.strip():
        out.append(cur)
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Cloudflare 可用节点两段式探测（TLS 证书校验 + Host 301 校验）")
    ap.add_argument("--input", help="候选节点文件，每行 ip 或 ip:port（# 开头为注释）")
    ap.add_argument("--nodes",
                    help="直接指定节点列表，逗号分隔，如 'ip:port,ip2:port2#注释'"
                         "（优先于 --input / --generate）")
    ap.add_argument("--generate", type=int, metavar="N",
                    help="从 Cloudflare 官方 IP 段采样 N 个候选 IP 并探测（不填端口时用 --ports）")
    ap.add_argument("--ports", default="443",
                    help="生成模式使用的探测端口，逗号分隔（默认 443）")
    ap.add_argument("--port", type=int, default=443,
                    help="输入文件里无端口时的默认端口（默认 443）")
    ap.add_argument("--out", default="usable_nodes.txt",
                    help="可用节点输出文件（默认 usable_nodes.txt）")
    ap.add_argument("--report", default="probe_report.txt",
                    help="全部节点两段探测明细（默认 probe_report.txt）")
    ap.add_argument("--save-candidates",
                    help="把生成的候选节点写入该文件，便于复用/排查")
    ap.add_argument("--workers", type=int, default=100, help="并发数（默认 100）")
    ap.add_argument("--timeout", type=float, default=5.0,
                    help="单节点每段探测超时秒数（默认 5）")
    ap.add_argument("--probe-host", default=DEFAULT_PROBE_HOST,
                    help="第二批 HTTP 请求的 Host/SNI（默认 crypto.cloudflare.com）")
    ap.add_argument("--expect-code", type=int, default=DEFAULT_EXPECT_CODE,
                    help="第二批期望的状态码（默认 301）")
    ap.add_argument("--scheme", choices=("https", "http"), default="https",
                    help="第二批请求协议（默认 https，与 TLS 端口配套）")
    ap.add_argument("--quiet", action="store_true", help="不逐条打印结果")
    args = ap.parse_args()

    ports = [int(p) for p in args.ports.split(",") if p.strip().isdigit()] or [443]

    if args.nodes:
        nodes = [n for part in split_nodes(args.nodes)
                 if (n := parse_node(part, args.port))]
    elif args.generate:
        nodes, cidrs = generate_nodes(args.generate, ports, args.timeout)
        print("[*] 已从 %d 个 CIDR 采样 %d 个候选节点" % (len(cidrs), len(nodes)))
        if args.save_candidates:
            ensure_dir(args.save_candidates)
            with open(args.save_candidates, "w", encoding="utf-8") as f:
                for ip, port in nodes:
                    f.write("%s:%d\n" % (ip, port))
            print("[*] 候选节点已写入 %s" % args.save_candidates)
    elif args.input:
        nodes = load_nodes(args.input, args.port)
    else:
        ap.error("请用 --input 指定候选文件，或用 --generate 采样生成")

    nodes = list(dict.fromkeys(nodes))
    print("[*] 待探测节点 %d 个，并发 %d，超时 %.1fs" % (len(nodes), args.workers, args.timeout))
    if not nodes:
        print("[!] 没有可探测的节点，退出")
        return

    def probe(node):
        ip, port = node
        ok1, note1 = tls_probe(ip, port, args.timeout)
        if not ok1:
            return ip, port, False, "第一批(TLS证书)", note1, ""
        ok2, note2 = http_probe(ip, port, args.timeout,
                                args.probe_host, args.expect_code, args.scheme)
        return ip, port, ok2, "第二批(HTTP %d)" % args.expect_code, note1, note2

    usable, report_lines = [], []
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(probe, n): n for n in nodes}
        for fut in concurrent.futures.as_completed(futs):
            ip, port, ok, stage, n1, n2 = fut.result()
            done += 1
            if ok:
                usable.append("%s:%d" % (ip, port))
                line = "%s:%d  [可用]    %s | %s" % (ip, port, n1, n2)
            else:
                line = "%s:%d  [不可用]  %s | %s | %s" % (ip, port, stage, n1, n2)
            report_lines.append(line)
            if not args.quiet and (ok or done % 50 == 0):
                print(line)

    ensure_dir(args.out)
    ensure_dir(args.report)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(usable) + ("\n" if usable else ""))
    with open(args.report, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines) + "\n")
    print("\n[+] 完成：探测 %d 个节点，可用 %d 个" % (done, len(usable)))
    print("[+] 可用节点 -> %s" % args.out)
    print("[+] 探测明细 -> %s" % args.report)


if __name__ == "__main__":
    main()
