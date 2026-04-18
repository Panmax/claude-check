#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Claude AI - 终极环境安全深度检测工具 (Pro 版)
融合本地网络防漏检测 (IPv6/DNS/时区) + 目标服务器 WAF 穿透探测
零依赖，原生支持 macOS / Linux / Windows
"""

import argparse
import datetime
import json
import os
import platform
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

# ─── 颜色 ───────────────────────────────────────────────────────────────

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    @classmethod
    def disable(cls):
        cls.GREEN = cls.RED = cls.YELLOW = cls.BLUE = cls.BOLD = cls.RESET = ''


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


def _fmt_offset(seconds):
    """将秒数格式化为 UTC±X.X 字符串。"""
    return f"UTC{seconds / 3600:+.1f}"

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
    """2. 落地 IP 质量与时区匹配度"""
    print(f"\n{Colors.BOLD}[*] 2. 落地 IP 质量与时区匹配度 (IP Quality & Timezone Match){Colors.RESET}")

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
            print(f"  {Colors.RED}⚠️  IP 质量风险: 检测为 [商用机房 Hosting / 代理节点]{Colors.RESET}"
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
                print(f"  {Colors.GREEN}✅ 伪装完美：本机时区与代理出口 IP 时区完全一致: "
                      f"{proxy_tz} ({_fmt_offset(proxy_offset_sec)}){Colors.RESET}")
            else:
                print(f"  {Colors.RED}❌ 时区不匹配！本机({_fmt_offset(local_offset_sec)}) "
                      f"vs 代理节点({_fmt_offset(proxy_offset_sec)}){Colors.RESET}")
                print(f"     -> 高危特征：Claude 会通过浏览器 JS 获取你的系统时间，"
                      f"并与你 IP 所在地的时间做对比。偏差证明了你是代理翻墙用户。请修改电脑系统时区！")

        ip_result['timezone_match'] = tz_match
        ip_result['proxy_tz'] = proxy_tz

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


def check_claude_web(results):
    """3. 探测 Claude 前端 Web 盾防御策略"""
    print(f"\n{Colors.BOLD}[*] 3. 探测 Claude 前端 Web 盾防御策略 (Cloudflare WAF Check){Colors.RESET}")

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
    """4. 逆向探测 Anthropic API 底层连通性"""
    print(f"\n{Colors.BOLD}[*] 4. 逆向探测 Anthropic API 底层连通性 (API Hard-Ban Check){Colors.RESET}")

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

# ─── 综合评估 ────────────────────────────────────────────────────────────

def calculate_risk(results):
    """根据各项检测结果计算综合风险等级。返回 (level, suggestions)。"""
    red_flags = 0
    yellow_flags = 0
    suggestions = []

    # IPv6
    if results.get('ipv6', {}).get('connected'):
        red_flags += 1
        suggestions.append('在网络设置中禁用 IPv6')

    # DNS
    dns_status = results.get('dns_leak', {}).get('status')
    if dns_status == 'leaked':
        red_flags += 1
        suggestions.append('在代理软件中开启「远程 DNS 解析」')
    elif dns_status == 'unknown':
        yellow_flags += 1

    # 时区
    tz_match = results.get('ip_quality', {}).get('timezone_match')
    if tz_match is False:
        red_flags += 1
        suggestions.append('修改系统时区为代理节点所在时区')

    # IP 质量
    ip_q = results.get('ip_quality', {})
    if ip_q.get('hosting') or ip_q.get('proxy'):
        yellow_flags += 1
        suggestions.append('考虑更换为住宅 IP / 原生 ISP 节点')

    # WAF
    waf_status = results.get('cloudflare_waf', {}).get('status')
    if waf_status == 'blocked':
        red_flags += 1
        suggestions.append('更换 IP 节点，当前 IP 段已被 Cloudflare 拦截')
    elif waf_status == 'js_challenge':
        yellow_flags += 1
        suggestions.append('当前 IP 需通过 JS Challenge，建议更换更干净的节点')

    # API
    api_status = results.get('api_connectivity', {}).get('status')
    if api_status == 'hard_banned':
        red_flags += 1
        suggestions.append('API 层面已被硬封，必须更换 IP 节点')
    elif api_status == 'error':
        yellow_flags += 1

    # 综合判定
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
    results['overall_risk'] = level
    results['suggestions'] = suggestions

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
    ip_clean = not (results.get('ip_quality', {}).get('hosting') or
                    results.get('ip_quality', {}).get('proxy'))
    waf_ok = results.get('cloudflare_waf', {}).get('status') == 'pass'
    waf_unknown = results.get('cloudflare_waf', {}).get('status') in ('unknown', 'error')
    api_ok = results.get('api_connectivity', {}).get('status') == 'reachable'
    api_unknown = results.get('api_connectivity', {}).get('status') in ('unknown', 'error')

    c = level_colors.get(level, '')
    print(f"\n{Colors.BOLD}====================== 综合风险评估 ================================{Colors.RESET}")
    print(f"  IPv6 泄漏    : {_status_icon(ipv6_ok)}")
    print(f"  DNS 泄漏     : {_status_icon(dns_ok if not dns_unknown else None)}")
    print(f"  时区匹配     : {_status_icon(tz_ok)}")
    print(f"  IP 质量      : {_status_icon(ip_clean if results.get('ip_quality', {}).get('status') == 'ok' else None)}")
    print(f"  Web WAF      : {_status_icon(waf_ok if not waf_unknown else None)}")
    print(f"  API 连通     : {_status_icon(api_ok if not api_unknown else None)}")
    print(f"\n  🔒 综合风险等级: {c}{Colors.BOLD}{level_labels.get(level, level)}{Colors.RESET}")

    if suggestions:
        print(f"  📋 建议: {'; '.join(suggestions)}")

    print(f"{Colors.BOLD}====================================================================={Colors.RESET}\n")

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

    if not args.skip_web:
        check_claude_web(results)
    else:
        results['cloudflare_waf'] = {'status': 'skipped'}
        if not args.json_output:
            print(f"\n{Colors.BOLD}[*] 3. Web WAF 检测 — 已跳过 (--skip-web){Colors.RESET}")

    if not args.skip_api:
        check_claude_api(results)
    else:
        results['api_connectivity'] = {'status': 'skipped'}
        if not args.json_output:
            print(f"\n{Colors.BOLD}[*] 4. API 连通性检测 — 已跳过 (--skip-api){Colors.RESET}")

    if args.json_output:
        level, suggestions = calculate_risk(results)
        results['overall_risk'] = level
        results['suggestions'] = suggestions
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
