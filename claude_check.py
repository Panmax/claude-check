#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Claude AI - 终极环境安全深度检测工具 (Pro 版)
融合本地网络防漏检测 (IPv6/DNS/时区/语言) + 目标服务器 WAF 穿透探测
零依赖，原生支持 macOS / Linux / Windows
"""

import argparse
import datetime
import json
import locale
import os
import platform
import re
import socket
import sys
import time
import urllib.error
import urllib.request

# ─── 常量 ───────────────────────────────────────────────────────────────

CHROME_UA = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/125.0.0.0 Safari/537.36'
)

CF_CHALLENGE_MARKERS = [
    'challenges.cloudflare.com',
    'cf-turnstile',
    '_cf_chl_opt',
    'managed_checking',
]

# 国家代码 → 常见系统语言前缀映射（用于语言匹配检测）
COUNTRY_LANG_MAP = {
    'US': ['en'], 'GB': ['en'], 'AU': ['en'], 'CA': ['en', 'fr'],
    'JP': ['ja'], 'KR': ['ko'], 'DE': ['de'], 'FR': ['fr'],
    'TW': ['zh'], 'HK': ['zh', 'en'], 'SG': ['en', 'zh'],
    'BR': ['pt'], 'RU': ['ru'], 'IN': ['en', 'hi'],
    'NL': ['nl', 'en'], 'SE': ['sv', 'en'], 'NO': ['no', 'nb', 'nn', 'en'],
    'DK': ['da', 'en'], 'FI': ['fi', 'en'], 'IT': ['it'],
    'ES': ['es'], 'MX': ['es'], 'AR': ['es'],
    'TH': ['th'], 'VN': ['vi'], 'PH': ['en', 'fil'],
    'MY': ['ms', 'en'], 'ID': ['id'],
    'TR': ['tr'], 'PL': ['pl'], 'CZ': ['cs'],
}

# ─── 颜色 ───────────────────────────────────────────────────────────────

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    DIM = '\033[2m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    @classmethod
    def disable(cls):
        for attr in ('GREEN', 'RED', 'YELLOW', 'BLUE', 'CYAN', 'MAGENTA',
                      'DIM', 'BOLD', 'RESET'):
            setattr(cls, attr, '')


def _init_colors(force_no_color=False):
    """初始化终端颜色支持。"""
    if force_no_color or not sys.stdout.isatty():
        Colors.disable()
        return
    if platform.system() == 'Windows':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            Colors.disable()

# ─── 工具函数 ────────────────────────────────────────────────────────────

def _urlopen_read(req, timeout=10):
    """发起 HTTP 请求并返回 (decoded_text, response_headers)。"""
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        charset = resp.headers.get_content_charset() or 'utf-8'
        return data.decode(charset), resp.headers


def _timed_request(url, timeout=10, headers=None):
    """发起请求并返回 (elapsed_ms, status_code)。仅测量延迟，不读取完整响应体。"""
    hdrs = {'User-Agent': CHROME_UA}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            _ = resp.read(1)  # 触发实际连接
            elapsed = (time.monotonic() - start) * 1000
            return elapsed, resp.status
    except urllib.error.HTTPError as e:
        elapsed = (time.monotonic() - start) * 1000
        return elapsed, e.code
    except Exception:
        return None, None


def _fmt_offset(seconds):
    """将秒数格式化为 UTC±X.X 字符串。"""
    return f"UTC{seconds / 3600:+.1f}"


def _fmt_latency(ms):
    """格式化延迟值并附加颜色。"""
    if ms is None:
        return f"{Colors.RED}超时{Colors.RESET}"
    if ms < 250:
        return f"{Colors.GREEN}{ms:.0f}ms (快){Colors.RESET}"
    elif ms < 500:
        return f"{Colors.YELLOW}{ms:.0f}ms (一般){Colors.RESET}"
    else:
        return f"{Colors.RED}{ms:.0f}ms (慢){Colors.RESET}"


def _get_system_lang():
    """获取系统语言前缀，如 'en'、'zh'。"""
    lang = os.environ.get('LANG') or os.environ.get('LANGUAGE') or ''
    if not lang:
        try:
            lang = locale.getdefaultlocale()[0] or ''
        except Exception:
            lang = ''
    # 提取语言前缀: zh_CN.UTF-8 -> zh, en_US -> en
    m = re.match(r'^([a-z]{2})', lang.lower())
    return m.group(1) if m else None

# ─── 检测模块 ────────────────────────────────────────────────────────────

def check_local_env(results):
    """1. 本地网络与防泄漏体检"""
    print(f"{Colors.BOLD}[*] 1. 本地网络与防泄漏体检 (Local Network & Leak Check){Colors.RESET}")

    # ── 代理环境变量 ──
    proxies = {k: v for k, v in os.environ.items()
               if k.lower() in ('http_proxy', 'https_proxy', 'all_proxy')}
    results['proxy_env'] = {'found': bool(proxies), 'vars': proxies}
    if proxies:
        print(f"  {Colors.GREEN}✅ 发现系统代理环境变量:{Colors.RESET}")
        for k, v in proxies.items():
            print(f"     - {k}: {v}")
    else:
        print(f"  {Colors.YELLOW}⚠️ 未检测到系统代理环境变量 (HTTP_PROXY等)，"
              f"可能依赖 Tun/Tap 虚拟网卡或路由器透明代理。{Colors.RESET}")

    # ── IPv6 泄漏检测 ──
    ipv6_connected, ipv6_addr = _check_ipv6()
    results['ipv6'] = {'connected': ipv6_connected, 'addr': ipv6_addr}
    if ipv6_connected:
        print(f"  {Colors.RED}❌ 警告: 检测到 IPv6 已开启 ({ipv6_addr}){Colors.RESET}")
        print(f"     -> 极度危险：多数代理软件不接管 IPv6，"
              f"会导致你的真实国内 IP 裸奔直连 Claude。强烈建议在网络设置中禁用 IPv6！")
    else:
        print(f"  {Colors.GREEN}✅ IPv6 处于关闭或不可达状态 (安全，无绕过代理泄漏风险){Colors.RESET}")

    # ── DNS 泄漏检测 ──
    # 注意：HTTP 方式的 DNS 检测可能经过代理的远程 DNS，
    # 检测结果反映的是代理出口的 DNS 而非本机真实 DNS。
    # 这对于判断"代理是否正确配置了远程 DNS"仍然有价值。
    dns_result = {'status': 'unknown', 'ip': None, 'geo': None}
    try:
        req = urllib.request.Request("http://edns.ip-api.com/json")
        text, _ = _urlopen_read(req, timeout=5)
        dns_data = json.loads(text)
        dns_ip = dns_data.get('dns', {}).get('ip', 'Unknown')
        dns_geo = dns_data.get('dns', {}).get('geo', 'Unknown')
        dns_result['ip'] = dns_ip
        dns_result['geo'] = dns_geo

        if 'China' in dns_geo or 'CN' in dns_geo:
            dns_result['status'] = 'leaked'
            print(f"  {Colors.RED}❌ DNS 发生泄漏！出口 DNS 为国内节点: {dns_ip} ({dns_geo}){Colors.RESET}")
            print(f"     -> 风控雷达：DNS 泄漏会直接暴露你的真实地理位置，"
                  f"请在代理软件中开启「远程 DNS 解析」。")
        else:
            dns_result['status'] = 'safe'
            print(f"  {Colors.GREEN}✅ DNS 无国内泄漏。海外出口 DNS 为: {dns_ip} ({dns_geo}){Colors.RESET}")
    except (urllib.error.URLError, socket.timeout):
        print(f"  {Colors.YELLOW}⚠️ DNS 泄漏检测超时或网络不通{Colors.RESET}")
    except (json.JSONDecodeError, KeyError):
        print(f"  {Colors.YELLOW}⚠️ DNS 泄漏检测返回数据异常{Colors.RESET}")
    results['dns_leak'] = dns_result

    # ── 本地时区 ──
    now = datetime.datetime.now(datetime.timezone.utc).astimezone()
    local_offset_sec = int(now.utcoffset().total_seconds())
    local_tz_name = now.tzname() or time.tzname[0]
    results['timezone'] = {'local_offset': local_offset_sec, 'local_tz': local_tz_name}
    print(f"  🕒 本机系统时区: {local_tz_name} ({_fmt_offset(local_offset_sec)})")

    # ── 本地语言 ──
    sys_lang = _get_system_lang()
    results['system_lang'] = sys_lang
    if sys_lang:
        print(f"  🌍 本机系统语言: {sys_lang}")


def _check_ipv6():
    """检测 IPv6 外部连通性。返回 (connected: bool, addr: str|None)。"""
    if not socket.has_ipv6:
        return False, None

    targets = [
        ("2001:4860:4860::8888", 53),   # Google DNS
        ("2606:4700:4700::1111", 53),    # Cloudflare DNS
    ]
    sock = None
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.settimeout(3)
        for target in targets:
            try:
                sock.connect(target)
                return True, sock.getsockname()[0]
            except OSError:
                continue
        return False, None
    except OSError:
        return False, None
    finally:
        if sock:
            sock.close()


def check_ip_attributes(results):
    """2. 落地 IP 质量与时区/语言匹配度"""
    print(f"\n{Colors.BOLD}[*] 2. 落地 IP 质量与环境匹配度 (IP Quality & Fingerprint Match){Colors.RESET}")

    url = ("http://ip-api.com/json/"
           "?fields=status,country,countryCode,city,isp,org,as,mobile,proxy,hosting,query,timezone,offset")
    ip_result = {'status': 'unknown'}

    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'curl/8.7.1'})
        text, _ = _urlopen_read(req, timeout=10)
        data = json.loads(text)

        if data.get('status') != 'success':
            ip_result['status'] = 'failed'
            print(f"  {Colors.RED}❌ 无法获取 IP 信息{Colors.RESET}")
            results['ip_quality'] = ip_result
            return

        ip_result.update({
            'status': 'ok',
            'ip': data.get('query'),
            'country': data.get('country'),
            'country_code': data.get('countryCode'),
            'city': data.get('city'),
            'isp': data.get('isp'),
            'as': data.get('as'),
            'hosting': data.get('hosting', False),
            'proxy': data.get('proxy', False),
        })

        print(f"  📍 物理位置: {data.get('country')} ({data.get('countryCode')}) - {data.get('city')}")
        print(f"  🌐 出口 IP : {data.get('query')}")
        print(f"  🏢 归属 ASN: {data.get('as')}")
        print(f"  📡 运营商  : {data.get('isp')}")

        # IP 属性判定
        is_hosting = data.get('hosting', False)
        is_proxy = data.get('proxy', False)
        if is_hosting or is_proxy:
            labels = []
            if is_hosting:
                labels.append('商用机房 Hosting')
            if is_proxy:
                labels.append('代理节点')
            print(f"  {Colors.RED}⚠️  IP 质量风险: 检测为 [{' / '.join(labels)}]{Colors.RESET}"
                  f" -> 极易引发连坐封号")
        else:
            print(f"  {Colors.GREEN}✅ IP 质量优秀: 检测为 [真实家庭宽带/原生ISP]{Colors.RESET}"
                  f" -> 适合防封")

        # 时区一致性校验
        proxy_offset_sec = data.get('offset')
        proxy_tz = data.get('timezone')
        local_offset_sec = results.get('timezone', {}).get('local_offset')
        tz_match = None

        if proxy_offset_sec is not None and local_offset_sec is not None:
            tz_match = (local_offset_sec == proxy_offset_sec)
            if tz_match:
                print(f"  {Colors.GREEN}✅ 时区匹配：本机时区与代理出口 IP 时区完全一致: "
                      f"{proxy_tz} ({_fmt_offset(proxy_offset_sec)}){Colors.RESET}")
            else:
                print(f"  {Colors.RED}❌ 时区不匹配！本机({_fmt_offset(local_offset_sec)}) "
                      f"vs 代理节点({_fmt_offset(proxy_offset_sec)}){Colors.RESET}")
                print(f"     -> 高危特征：Claude 会通过浏览器 JS 获取你的系统时间，"
                      f"并与你 IP 所在地的时间做对比。偏差证明了你是代理翻墙用户。请修改电脑系统时区！")

        ip_result['timezone_match'] = tz_match
        ip_result['proxy_tz'] = proxy_tz

        # 语言一致性校验
        country_code = data.get('countryCode', '')
        sys_lang = results.get('system_lang')
        lang_match = None

        if sys_lang and country_code in COUNTRY_LANG_MAP:
            expected_langs = COUNTRY_LANG_MAP[country_code]
            lang_match = sys_lang in expected_langs
            ip_result['lang_match'] = lang_match
            if lang_match:
                print(f"  {Colors.GREEN}✅ 语言匹配：系统语言 ({sys_lang}) 与出口地区 ({country_code}) 一致{Colors.RESET}")
            else:
                print(f"  {Colors.YELLOW}⚠️ 语言不匹配：系统语言 ({sys_lang}) 与出口地区 ({country_code}) "
                      f"常用语言 ({'/'.join(expected_langs)}) 不一致{Colors.RESET}")
                print(f"     -> 风控参考：语言环境不一致是常见的代理用户特征，"
                      f"建议修改系统语言或使用浏览器语言覆盖。")
        else:
            ip_result['lang_match'] = None

    except urllib.error.HTTPError as e:
        if e.code == 429:
            retry_after = e.headers.get('Retry-After', '60')
            print(f"  {Colors.YELLOW}⚠️ IP 查询 API 限流 (429)，请 {retry_after} 秒后重试{Colors.RESET}")
        else:
            print(f"  {Colors.RED}❌ IP 查询异常 (HTTP {e.code}){Colors.RESET}")
    except (urllib.error.URLError, socket.timeout) as e:
        print(f"  {Colors.RED}❌ 网络请求异常: {e}{Colors.RESET}")
    except (json.JSONDecodeError, KeyError):
        print(f"  {Colors.RED}❌ IP 查询返回数据异常{Colors.RESET}")

    results['ip_quality'] = ip_result


def check_cloudflare_trace(results):
    """3. Cloudflare Trace 真实出口 IP 对比"""
    print(f"\n{Colors.BOLD}[*] 3. Cloudflare Trace 真实出口 IP (Claude 视角){Colors.RESET}")

    trace_result = {'status': 'unknown'}

    try:
        req = urllib.request.Request("https://claude.ai/cdn-cgi/trace",
                                     headers={'User-Agent': CHROME_UA})
        text, _ = _urlopen_read(req, timeout=10)

        # 解析 Cloudflare trace 键值对格式: key=value
        trace_data = {}
        for line in text.strip().splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                trace_data[k.strip()] = v.strip()

        cf_ip = trace_data.get('ip', '')
        cf_loc = trace_data.get('loc', '')
        cf_colo = trace_data.get('colo', '')  # 边缘节点代码，如 LAX, NRT

        trace_result.update({
            'status': 'ok',
            'ip': cf_ip,
            'loc': cf_loc,
            'colo': cf_colo,
        })

        print(f"  🎯 Claude 看到的 IP: {cf_ip}")
        print(f"  📍 Cloudflare 边缘 : {cf_colo} ({cf_loc})")

        # 对比 ip-api 获取的 IP
        ipapi_ip = results.get('ip_quality', {}).get('ip', '')
        if ipapi_ip and cf_ip:
            if ipapi_ip == cf_ip:
                trace_result['ip_consistent'] = True
                print(f"  {Colors.GREEN}✅ IP 一致：ip-api ({ipapi_ip}) = Cloudflare ({cf_ip})，"
                      f"无分流泄漏{Colors.RESET}")
            else:
                trace_result['ip_consistent'] = False
                print(f"  {Colors.YELLOW}⚠️ IP 不一致：ip-api ({ipapi_ip}) ≠ Cloudflare ({cf_ip}){Colors.RESET}")
                print(f"     -> 可能存在分流/隧道配置差异，部分流量未经代理。"
                      f"请检查代理规则是否覆盖 claude.ai 域名。")
        else:
            trace_result['ip_consistent'] = None

    except urllib.error.HTTPError as e:
        trace_result['status'] = f'http_{e.code}'
        print(f"  {Colors.YELLOW}⚠️ Cloudflare Trace 异常 (HTTP {e.code}){Colors.RESET}")
    except (urllib.error.URLError, socket.timeout) as e:
        trace_result['status'] = 'error'
        print(f"  {Colors.RED}❌ Cloudflare Trace 请求失败: {e}{Colors.RESET}")

    results['cf_trace'] = trace_result


def check_claude_web(results):
    """4. 探测 Claude 前端 Web 盾防御策略"""
    print(f"\n{Colors.BOLD}[*] 4. 探测 Claude 前端 Web 盾防御策略 (Cloudflare WAF Check){Colors.RESET}")

    url = "https://claude.ai/login"
    req = urllib.request.Request(url, headers={'User-Agent': CHROME_UA})
    waf_result = {'status': 'unknown'}

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body_snippet = resp.read(4096).decode('utf-8', errors='ignore')
            has_challenge = any(m in body_snippet for m in CF_CHALLENGE_MARKERS)

            if has_challenge:
                waf_result['status'] = 'js_challenge'
                print(f"  {Colors.YELLOW}⚠️ 收到 HTTP 200 但包含 Cloudflare JS Challenge，"
                      f"浏览器访问时需通过人机验证。{Colors.RESET}")
                print(f"     -> 该 IP 可能信誉较低，被 Cloudflare 标记为需验证。")
            else:
                waf_result['status'] = 'pass'
                print(f"  {Colors.GREEN}✅ 网页直连通过: 无 Cloudflare 人机拦截，"
                      f"Web 盾前置放行！{Colors.RESET}")

    except urllib.error.HTTPError as e:
        cf_status = e.headers.get('cf-mitigated', '')
        if e.code == 403 and 'challenge' in cf_status:
            waf_result['status'] = 'blocked'
            print(f"  {Colors.RED}❌ 网页被拦截 (HTTP 403): 该 IP 触发了 Cloudflare 强验证盾。{Colors.RESET}")
            print(f"     -> 说明：该 IP 段有滥用黑历史，如果强行注册，"
                  f"接码和账号关联大概率被污染。")
        else:
            waf_result['status'] = f'http_{e.code}'
            print(f"  {Colors.YELLOW}⚠️ 网页状态异常 (HTTP {e.code}): "
                  f"节点可能被部分限制{Colors.RESET}")
    except (urllib.error.URLError, socket.timeout) as e:
        waf_result['status'] = 'error'
        print(f"  {Colors.RED}❌ 网页访问失败: {e}{Colors.RESET}")

    results['cloudflare_waf'] = waf_result


def check_claude_api(results):
    """5. 逆向探测 Anthropic API 底层连通性"""
    print(f"\n{Colors.BOLD}[*] 5. 逆向探测 Anthropic API 底层连通性 (API Hard-Ban Check){Colors.RESET}")

    url = "https://api.anthropic.com/v1/messages"
    req = urllib.request.Request(url, data=b'{}', headers={
        'User-Agent': CHROME_UA,
        'x-api-key': 'ant-api-fake-probe-key',
        'anthropic-version': '2023-06-01',
        'Content-Type': 'application/json',
    }, method='POST')
    api_result = {'status': 'unknown'}

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            api_result['status'] = f'http_{resp.status}'
            print(f"  {Colors.YELLOW}⚠️ API 返回非预期成功状态 (HTTP {resp.status}){Colors.RESET}")
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')
        if e.code == 401 and 'authentication_error' in body:
            api_result['status'] = 'reachable'
            print(f"  {Colors.GREEN}✅ API 穿透成功: 流量直达 Anthropic 核心后端，"
                  f"IP 未在硬封锁黑名单中！{Colors.RESET}")
        elif e.code == 403:
            api_result['status'] = 'hard_banned'
            print(f"  {Colors.RED}❌ API 被硬封锁 (HTTP 403): "
                  f"该节点已被官方彻底拉黑，100% 无法调用 API！{Colors.RESET}")
        else:
            api_result['status'] = f'http_{e.code}'
            print(f"  {Colors.YELLOW}⚠️ API 状态异常 (HTTP {e.code}): "
                  f"未知封锁策略{Colors.RESET}")
    except (urllib.error.URLError, socket.timeout) as e:
        api_result['status'] = 'error'
        print(f"  {Colors.RED}❌ API 连接失败: {e}{Colors.RESET}")

    results['api_connectivity'] = api_result


def check_latency_and_status(results):
    """6. 延迟测试与服务状态"""
    print(f"\n{Colors.BOLD}[*] 6. 连接延迟与 Anthropic 服务状态 (Latency & Status){Colors.RESET}")

    latency_result = {}

    # ── 延迟测试 ──
    targets = [
        ("claude.ai", "https://claude.ai/cdn-cgi/trace"),
        ("api.anthropic.com", "https://api.anthropic.com"),
    ]
    for name, url in targets:
        ms, code = _timed_request(url, timeout=10)
        latency_result[name] = {'latency_ms': round(ms, 1) if ms else None, 'status_code': code}
        print(f"  ⏱️  {name:25s} : {_fmt_latency(ms)}"
              + (f" {Colors.DIM}(HTTP {code}){Colors.RESET}" if code else ""))

    # ── Anthropic 官方服务状态 ──
    status_result = {'status': 'unknown'}
    try:
        req = urllib.request.Request("https://status.anthropic.com/api/v2/status.json",
                                     headers={'User-Agent': CHROME_UA})
        text, _ = _urlopen_read(req, timeout=8)
        status_data = json.loads(text)
        indicator = status_data.get('status', {}).get('indicator', '')
        description = status_data.get('status', {}).get('description', '')
        status_result = {'status': indicator, 'description': description}

        indicator_map = {
            'none': (Colors.GREEN, '✅', '所有系统正常'),
            'minor': (Colors.YELLOW, '⚠️', '部分系统异常'),
            'major': (Colors.RED, '❌', '主要系统故障'),
            'critical': (Colors.RED, '🚨', '严重故障'),
        }
        color, icon, label = indicator_map.get(indicator, (Colors.YELLOW, '❓', indicator))
        print(f"  📡 Anthropic 服务状态  : {color}{icon} {description or label}{Colors.RESET}")

    except Exception:
        print(f"  {Colors.YELLOW}⚠️ 无法获取 Anthropic 服务状态{Colors.RESET}")

    results['latency'] = latency_result
    results['service_status'] = status_result

# ─── 信任评分 ────────────────────────────────────────────────────────────

def calculate_trust_score(results):
    """
    计算 0-100 的信任评分。
    满分 100，各项扣分。分数越高越安全。
    """
    score = 100
    details = {}

    # IPv6 泄漏 (-20)
    if results.get('ipv6', {}).get('connected'):
        score -= 20
        details['ipv6'] = -20
    else:
        details['ipv6'] = 0

    # DNS 泄漏 (-20)
    dns_status = results.get('dns_leak', {}).get('status')
    if dns_status == 'leaked':
        score -= 20
        details['dns'] = -20
    elif dns_status == 'unknown':
        score -= 5
        details['dns'] = -5
    else:
        details['dns'] = 0

    # 时区匹配 (-15)
    tz_match = results.get('ip_quality', {}).get('timezone_match')
    if tz_match is False:
        score -= 15
        details['timezone'] = -15
    elif tz_match is None:
        score -= 3
        details['timezone'] = -3
    else:
        details['timezone'] = 0

    # 语言匹配 (-5)
    lang_match = results.get('ip_quality', {}).get('lang_match')
    if lang_match is False:
        score -= 5
        details['language'] = -5
    else:
        details['language'] = 0

    # IP 质量 (-15: hosting, -10: proxy only)
    ip_q = results.get('ip_quality', {})
    if ip_q.get('hosting'):
        score -= 15
        details['ip_type'] = -15
    elif ip_q.get('proxy'):
        score -= 10
        details['ip_type'] = -10
    else:
        details['ip_type'] = 0

    # IP 一致性 (-10)
    cf_consistent = results.get('cf_trace', {}).get('ip_consistent')
    if cf_consistent is False:
        score -= 10
        details['ip_consistency'] = -10
    else:
        details['ip_consistency'] = 0

    # WAF (-15)
    waf_status = results.get('cloudflare_waf', {}).get('status')
    if waf_status == 'blocked':
        score -= 15
        details['waf'] = -15
    elif waf_status == 'js_challenge':
        score -= 8
        details['waf'] = -8
    elif waf_status not in ('pass', 'skipped'):
        score -= 3
        details['waf'] = -3
    else:
        details['waf'] = 0

    # API (-15)
    api_status = results.get('api_connectivity', {}).get('status')
    if api_status == 'hard_banned':
        score -= 15
        details['api'] = -15
    elif api_status == 'error':
        score -= 5
        details['api'] = -5
    elif api_status not in ('reachable', 'skipped'):
        score -= 3
        details['api'] = -3
    else:
        details['api'] = 0

    score = max(0, score)
    return score, details


def _score_label(score):
    """返回 (颜色, 标签)。"""
    if score >= 90:
        return Colors.GREEN, '极度纯净'
    elif score >= 75:
        return Colors.GREEN, '纯净'
    elif score >= 50:
        return Colors.YELLOW, '良好'
    elif score >= 25:
        return Colors.YELLOW, '中性'
    else:
        return Colors.RED, '危险'


def _score_bar(score):
    """生成分数进度条。"""
    filled = score // 5  # 0-20 格
    empty = 20 - filled
    color, _ = _score_label(score)
    return f"{color}{'█' * filled}{Colors.DIM}{'░' * empty}{Colors.RESET}"

# ─── 综合评估 ────────────────────────────────────────────────────────────

def calculate_risk(results):
    """根据各项检测结果计算综合风险等级。返回 (level, suggestions)。"""
    red_flags = 0
    yellow_flags = 0
    suggestions = []

    if results.get('ipv6', {}).get('connected'):
        red_flags += 1
        suggestions.append('在网络设置中禁用 IPv6')

    dns_status = results.get('dns_leak', {}).get('status')
    if dns_status == 'leaked':
        red_flags += 1
        suggestions.append('在代理软件中开启「远程 DNS 解析」')
    elif dns_status == 'unknown':
        yellow_flags += 1

    tz_match = results.get('ip_quality', {}).get('timezone_match')
    if tz_match is False:
        red_flags += 1
        suggestions.append('修改系统时区为代理节点所在时区')

    lang_match = results.get('ip_quality', {}).get('lang_match')
    if lang_match is False:
        yellow_flags += 1
        suggestions.append('修改系统语言为代理节点所在地区常用语言')

    ip_q = results.get('ip_quality', {})
    if ip_q.get('hosting') or ip_q.get('proxy'):
        yellow_flags += 1
        suggestions.append('考虑更换为住宅 IP / 原生 ISP 节点')

    cf_consistent = results.get('cf_trace', {}).get('ip_consistent')
    if cf_consistent is False:
        yellow_flags += 1
        suggestions.append('检查代理分流规则，确保 claude.ai 流量经过代理')

    waf_status = results.get('cloudflare_waf', {}).get('status')
    if waf_status == 'blocked':
        red_flags += 1
        suggestions.append('更换 IP 节点，当前 IP 段已被 Cloudflare 拦截')
    elif waf_status == 'js_challenge':
        yellow_flags += 1
        suggestions.append('当前 IP 需通过 JS Challenge，建议更换更干净的节点')

    api_status = results.get('api_connectivity', {}).get('status')
    if api_status == 'hard_banned':
        red_flags += 1
        suggestions.append('API 层面已被硬封，必须更换 IP 节点')
    elif api_status == 'error':
        yellow_flags += 1

    if red_flags >= 2:
        level = 'CRITICAL'
    elif red_flags >= 1:
        level = 'HIGH'
    elif yellow_flags >= 1:
        level = 'MEDIUM'
    else:
        level = 'LOW'

    return level, suggestions


def print_summary(results):
    """打印综合风险评估报告。"""
    level, suggestions = calculate_risk(results)
    score, score_details = calculate_trust_score(results)
    results['overall_risk'] = level
    results['suggestions'] = suggestions
    results['trust_score'] = score
    results['trust_score_details'] = score_details

    level_colors = {
        'LOW': Colors.GREEN,
        'MEDIUM': Colors.YELLOW,
        'HIGH': Colors.RED,
        'CRITICAL': Colors.RED,
    }
    level_labels = {
        'LOW': '低风险 (LOW)',
        'MEDIUM': '中风险 (MEDIUM)',
        'HIGH': '高风险 (HIGH)',
        'CRITICAL': '极高风险 (CRITICAL)',
    }

    def _status_icon(ok):
        if ok is True:
            return f'{Colors.GREEN}✅ 安全{Colors.RESET}'
        elif ok is False:
            return f'{Colors.RED}❌ 异常{Colors.RESET}'
        return f'{Colors.YELLOW}⚠️ 未知{Colors.RESET}'

    ipv6_ok = not results.get('ipv6', {}).get('connected', False)
    dns_ok = results.get('dns_leak', {}).get('status') == 'safe'
    dns_unknown = results.get('dns_leak', {}).get('status') == 'unknown'
    tz_ok = results.get('ip_quality', {}).get('timezone_match')
    lang_ok = results.get('ip_quality', {}).get('lang_match')
    ip_clean = not (results.get('ip_quality', {}).get('hosting') or
                    results.get('ip_quality', {}).get('proxy'))
    cf_consistent = results.get('cf_trace', {}).get('ip_consistent')
    cf_unknown = results.get('cf_trace', {}).get('status') in ('unknown', 'error')
    waf_ok = results.get('cloudflare_waf', {}).get('status') == 'pass'
    waf_unknown = results.get('cloudflare_waf', {}).get('status') in ('unknown', 'error', 'skipped')
    api_ok = results.get('api_connectivity', {}).get('status') == 'reachable'
    api_unknown = results.get('api_connectivity', {}).get('status') in ('unknown', 'error', 'skipped')

    c = level_colors.get(level, '')
    score_color, score_text = _score_label(score)

    print(f"\n{Colors.BOLD}{'=' * 68}")
    print(f"                        综合风险评估")
    print(f"{'=' * 68}{Colors.RESET}")

    # 信任评分（大字显示）
    print(f"\n  {Colors.BOLD}信任评分{Colors.RESET}  {score_color}{Colors.BOLD}{score}/100{Colors.RESET}"
          f"  {score_color}{score_text}{Colors.RESET}")
    print(f"  {_score_bar(score)}\n")

    # 检测项明细
    print(f"  {'检测项':<14s}{'结果':s}")
    print(f"  {'─' * 40}")
    print(f"  {'IPv6 泄漏':<12s}: {_status_icon(ipv6_ok)}")
    print(f"  {'DNS 泄漏':<12s}: {_status_icon(dns_ok if not dns_unknown else None)}")
    print(f"  {'时区匹配':<12s}: {_status_icon(tz_ok)}")
    print(f"  {'语言匹配':<12s}: {_status_icon(lang_ok)}")
    print(f"  {'IP 质量':<12s}: {_status_icon(ip_clean if results.get('ip_quality', {}).get('status') == 'ok' else None)}")
    print(f"  {'IP 一致性':<11s}: {_status_icon(cf_consistent if not cf_unknown else None)}")
    print(f"  {'Web WAF':<13s}: {_status_icon(waf_ok if not waf_unknown else None)}")
    print(f"  {'API 连通':<12s}: {_status_icon(api_ok if not api_unknown else None)}")

    print(f"\n  🔒 综合风险等级: {c}{Colors.BOLD}{level_labels.get(level, level)}{Colors.RESET}")

    if suggestions:
        print(f"\n  📋 改进建议:")
        for i, s in enumerate(suggestions, 1):
            print(f"     {i}. {s}")

    print(f"\n{Colors.BOLD}{'=' * 68}{Colors.RESET}\n")

# ─── 入口 ────────────────────────────────────────────────────────────────

def print_banner():
    print(f"{Colors.BLUE}{Colors.BOLD}")
    print("================================================================")
    print("       🤖 Claude AI - 终极环境安全深度检测工具 (Pro 版)         ")
    print("================================================================")
    print(f"{Colors.RESET}")


def parse_args():
    parser = argparse.ArgumentParser(
        description='Claude AI 环境安全深度检测工具 - 一键检查代理环境是否安全',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--skip-api', action='store_true',
                        help='跳过 API 连通性检测')
    parser.add_argument('--skip-web', action='store_true',
                        help='跳过 Web WAF 检测')
    parser.add_argument('--json', action='store_true', dest='json_output',
                        help='以 JSON 格式输出结果（适合脚本集成）')
    parser.add_argument('--no-color', action='store_true',
                        help='禁用彩色输出')
    return parser.parse_args()


def main():
    args = parse_args()
    _init_colors(force_no_color=args.no_color or args.json_output)

    if not args.json_output:
        print_banner()

    results = {}

    check_local_env(results)
    check_ip_attributes(results)
    check_cloudflare_trace(results)

    if not args.skip_web:
        check_claude_web(results)
    else:
        results['cloudflare_waf'] = {'status': 'skipped'}
        if not args.json_output:
            print(f"\n{Colors.BOLD}[*] 4. Web WAF 检测 — 已跳过 (--skip-web){Colors.RESET}")

    if not args.skip_api:
        check_claude_api(results)
    else:
        results['api_connectivity'] = {'status': 'skipped'}
        if not args.json_output:
            print(f"\n{Colors.BOLD}[*] 5. API 连通性检测 — 已跳过 (--skip-api){Colors.RESET}")

    check_latency_and_status(results)

    if args.json_output:
        level, suggestions = calculate_risk(results)
        score, score_details = calculate_trust_score(results)
        results['overall_risk'] = level
        results['suggestions'] = suggestions
        results['trust_score'] = score
        results['trust_score_details'] = score_details
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        print_summary(results)

    # 退出码: 0=LOW, 1=HIGH/CRITICAL, 2=MEDIUM
    level = results.get('overall_risk', 'LOW')
    if level in ('HIGH', 'CRITICAL'):
        sys.exit(1)
    elif level == 'MEDIUM':
        sys.exit(2)
    sys.exit(0)


if __name__ == '__main__':
    main()
