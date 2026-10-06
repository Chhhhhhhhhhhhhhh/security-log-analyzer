# 从 urllib 库导入 parse 子模块，用于 URL 解码（parse.unquote）
from urllib import parse
# 从 collections 导入 Counter，用于统计元素出现次数（比手写 dict 计数更方便）
from collections import Counter
# 导入 json，用于把生成的报告写入 JSON 文件
import json
# 导入 argparse，用于解析命令行参数（比如 -l 日志文件、-t 阈值）
import argparse
# 导入 ipaddress，用于验证 IP 地址格式是否合法
import ipaddress
# 从 datetime 导入 datetime，用于解析日志时间戳和计算时间跨度
from datetime import datetime
from ai_analyzer import run_ai_analysis
from report_generator import generate_markdown_report
from threat_intel import lookup_ip_info

# 严重级别排序字典：用于比较两个级别谁更高（数值越大级别越高）
# 比如 SEVERITY_ORDER["HIGH"]=2 > SEVERITY_ORDER["MEDIUM"]=1
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

# 风险分数封顶值：计算单个 IP 总风险分时，每种攻击特征的命中次数最多算 CAP 次
# 防止某一种攻击被疯狂重复请求导致风险分无限累加
CAP = 10

# 扫描行为阈值：某个 IP 返回 404 的次数达到这个数，就被认为是在扫描目录
SCAN_THRESHOLD = 3

def load_rules(rule_file="rules.json"):
    with open(rule_file, "r", encoding="utf-8") as f:
        return json.load(f)

patterns = load_rules()

def parse_nginx_log(line):
    """
    解析 Nginx 日志的一行，把文本拆成结构化字段。
    期望格式：IP - - [时间] "请求行" 状态码 字节数 "referer" "user_agent"
    :param line: 日志文件中的一行文本
    :return: 解析成功返回字典，失败返回 None
    """
    # 用双引号 " 分割日志行
    # 因为请求行、referer、user_agent 都是被双引号包起来的
    # 分割后 parts 应该有 7 个元素：[IP前部分, 请求行, 状态码字节, referer, 空, user_agent, 空]
    parts = line.split('"')

    # 如果分割后不是 7 段，说明日志格式不符合预期，返回 None
    if len(parts) != 7:
        return None

    # parts[0] 是双引号前面的部分，包含 IP、时间戳等，去掉首尾空格
    first_part = parts[0].strip()

    # parts[1] 是请求行，比如 "GET /login HTTP/1.1"
    request_part = parts[1].strip()

    # 再用空格分割第一部分
    # 预期：[IP, -, -, [时间], ]  共 5 个元素
    first_parts = first_part.split()

    # 如果不是 5 段，格式不对，返回 None
    if len(first_parts) != 5:
        return None

    # IP 是第一部分的第一个元素
    ip = first_parts[0]

    # 验证 IP 格式是否合法，不合法就返回 None
    if not is_valid_ip(ip):
        return None

    # 时间戳是 first_parts[3] 和 first_parts[4] 拼接，比如 [02/Sep/2026:12:00:00 +0800]
    timestamp = " ".join(first_parts[3:5])

    # 分割请求行：METHOD URL PROTOCOL
    request_parts = request_part.split()

    # 至少要有 METHOD、URL、PROTOCOL 三段
    if len(request_parts) < 3:
        return None

    method = request_parts[0]                   # 请求方法，如 GET、POST

    # URL 可能包含空格，所以取第一个到倒数第二个之间所有部分拼起来
    url = " ".join(request_parts[1:-1])

    protocol = request_parts[-1]                # 最后一段是协议，如 HTTP/1.1

    # parts[2] 是状态码和字节数，比如 " 200 1234"
    status_size = parts[2].split()
    if len(status_size) != 2:
        return None

    # 第一个是 HTTP 状态码，转成整数
    status = int(status_size[0])

    # 第二个是响应字节数，"-" 表示没有响应体，记为 0
    size = int(status_size[1]) if status_size[1] != '-' else 0

    # parts[3] 是 referer（来源页面）
    referer = parts[3]

    # parts[5] 是 user_agent（浏览器信息）
    user_agent = parts[5]

    # 把所有解析出的字段打包成字典返回
    return {
        "ip": ip,
        "timestamp": timestamp,
        "method": method,
        "url": url,
        "protocol": protocol,
        "status": status,
        "size": size,
        "referer": referer,
        "user_agent": user_agent
    }

def is_valid_ip(ip):
    """
    检查 IP 地址格式是否合法。
    :param ip: 待检查的 IP 字符串
    :return: 合法返回 True，不合法返回 False
    """
    try:
        # ipaddress.ip_address 能解析 IPv4 和 IPv6，格式不对会抛 ValueError
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def normalize_log(log_data):
    """
    对日志中的 URL 做归一化处理，把变形的攻击特征还原成标准形式，方便后续匹配。
    :param log_data: 解析后的日志字典
    :return: 处理后的日志字典（url 字段被修改）
    """
    # parse.unquote 把 URL 编码的字符还原，比如 %27 还原成 '，%3C 还原成 <
    # 这样像 %3Cscript 这样的编码攻击也能被 "<script" 特征匹配到
    url = parse.unquote(log_data["url"])
    # 去掉 SQL 注释 /**/，攻击者常用它混淆特征，去掉后 union/**/select 变成 unionselect
    url = url.replace("/**/", "")

    log_data["url"] = url

    return log_data

def detect_attacks(log_data, line):
    """
    对归一化后的日志进行攻击特征匹配，返回所有命中的攻击告警。
    """
    ip = log_data["ip"]
    url = log_data["url"]
    status = log_data["status"]
    user_agent = log_data.get("user_agent", "").lower()

    alerts = []

    # 遍历 rules.json 里的每一条规则
    for pattern, rule in patterns.items():
        matched = False

        # 1. 如果是黑客扫描器或脚本客户端，检查 User-Agent
        if rule["type"] in ("Scanner_Tool", "Script_Client"):
            if pattern in user_agent:
                matched = True

        # 2. 否则是常规 Web 漏洞载荷（SQLi、XSS 等），检查 URL
        else:
            if pattern in url.lower():
                matched = True

        # 如果命中特征，构造一条标准告警记录
        if matched:
            alert = {
                "ip": ip,
                "pattern": pattern,                      # 命中的特征字符串
                "level": rule["severity"],               # 严重级别
                "type": rule["type"],                   # 攻击类型
                "url": url,
                "status": status,                        # HTTP 状态码
                "timestamp": log_data["timestamp"],      # 时间戳
                "line": line                             # 原始日志行（证据）
            }
            alerts.append(alert)

    return alerts

def count_ips(ips):
    """
    统计所有 IP 的访问次数。
    :param ips: IP 地址列表（每个请求一个 IP，可能重复）
    :return: Counter 对象，键是 IP，值是访问次数
    """
    # Counter(ips) 会自动统计列表中每个元素出现的次数
    ip_count = Counter(ips)

    return ip_count

def count_attacks_by_ip(alerts):
    """
    统计每个 IP 的攻击总次数（使用聚合后的 count 字段）。
    :param alerts: 告警列表（已按 IP+pattern+status 聚合，带 count 字段）
    :return: Counter 对象，键是 IP，值是该 IP 的攻击总次数
    """
    attack_count = Counter()

    for alert in alerts:
        # 每条告警的 count 是该特征出现的次数，累加起来就是该 IP 的总攻击次数
        # alert.get("count", 1) 表示取 count 字段，没有则默认 1
        attack_count[alert["ip"]] += alert.get("count", 1)

    return attack_count

def build_ip_behavior(ip_count, attack_count, alerts):
    """
    构建每个 IP 的行为画像，包括访问次数、攻击次数、攻击率、时间跨度、攻击频率。
    :param ip_count: 所有 IP 的访问次数统计
    :param attack_count: 所有 IP 的攻击次数统计
    :param alerts: 告警列表
    :return: 字典，键是 IP，值是行为画像字典
    """

    behavior = {}

    # 遍历所有访问过的 IP（不只是攻击 IP，也要包含正常访问的 IP）
    for ip, request_count in ip_count.items():
        # 取出该 IP 的攻击次数，没有则为 0
        attack = attack_count.get(ip, 0)

        # 筛选出属于该 IP 的所有告警
        ip_alerts = [
            alert for alert in alerts if alert["ip"] == ip
        ]

        # 如果该 IP 有告警，计算攻击时间跨度
        if ip_alerts:
            times = []
            for alert in ip_alerts:
                # datetime.strptime 把时间戳字符串解析成 datetime 对象
                # 格式字符串 [%d/%b/%Y:%H:%M:%S %z] 对应 [02/Sep/2026:12:00:00 +0800]
                # 记录首次出现时间
                times.append(datetime.strptime(alert["timestamp"], "[%d/%b/%Y:%H:%M:%S %z]"))
                # 记录最后出现时间
                times.append(datetime.strptime(alert["last_seen"], "[%d/%b/%Y:%H:%M:%S %z]"))

            # 最大时间减最小时间，得到攻击时间跨度（秒）
            attack_time_span = (max(times) - min(times)).total_seconds()
        else:
            attack_time_span = 0

        # 计算攻击频率：攻击次数 / 时间跨度（每秒多少次攻击）
        # max(attack_time_span, 1) 防止除以 0 或极小的数
        if attack_time_span > 0:
            attack_frequency = attack / max(attack_time_span, 1)
        else:
            attack_frequency = 0

        # 组装该 IP 的行为画像
        behavior[ip] = {
            "request_count": request_count,                       # 总请求次数
            "attack_count": attack,                               # 攻击次数
            "attack_rate": attack / request_count,                # 攻击率（攻击占比）
            "attack_time_span": attack_time_span,                 # 攻击时间跨度（秒）
            "attack_frequency": attack_frequency                  # 攻击频率（次/秒）
        }

    return behavior

def get_attack_types_by_ip(alerts):
    """
    统计每个 IP 涉及的攻击类型集合（去重）。
    :param alerts: 告警列表
    :return: 字典，键是 IP，值是该 IP 攻击类型的集合（set）
    """
    attack_types = {}

    for alert in alerts:
        ip = alert["ip"]
        attack_type = alert["type"]

        # 如果这个 IP 还没出现过，先建一个空集合
        if ip not in attack_types:
            attack_types[ip] = set()

        # 把攻击类型加入集合，集合自动去重
        attack_types[ip].add(attack_type)

    return attack_types

def build_ip_profile(behavior, attack_types, scores):
    """
    把行为画像、攻击类型、风险分数合并成完整的 IP 画像。
    :param behavior: build_ip_behavior 的输出
    :param attack_types: get_attack_types_by_ip 的输出
    :param scores: build_ip_scores 的输出
    :return: 字典，键是 IP，值是完整画像
    """
    profiles = {}

    for ip, data in behavior.items():
        # 取出该 IP 的攻击类型集合，没有则为空集合
        types = attack_types.get(ip, set())
        # 取出该 IP 的风险分数字典，没有则为空字典
        s = scores.get(ip, {})

        intel = lookup_ip_info(ip)

        profiles[ip] = {
            "request_count": data["request_count"],            # 总请求数
            "attack_count": data["attack_count"],              # 攻击次数
            "attack_rate": data["attack_rate"],                # 攻击率
            "attack_types": list(types),                       # 攻击类型列表（集合转列表）
            "attack_type_count": len(types),                   # 攻击类型数量
            "attack_time_span": data["attack_time_span"],      # 攻击时间跨度
            "attack_frequency": data["attack_frequency"],      # 攻击频率
            "max_severity": s.get("max_severity"),             # 最高严重级别
            "total_risk_score": s.get("total_risk_score", 0),   # 总风险分数
            "location": intel["location"],
            "isp": intel["isp"]
        }

    return profiles

def build_ip_scores(alerts):
    """
    计算每个 IP 的总风险分数和最高严重级别。
    每种攻击特征的命中次数会被封顶（最多算 CAP 次），防止单点刷分。
    :param alerts: 告警列表（已聚合，带 count 字段）
    :return: 字典，键是 IP，值是 {"total_risk_score": 分数, "max_severity": 级别}
    """
    scores = {}

    for alert in alerts:
        ip = alert["ip"]
        pattern = alert["pattern"]
        count = alert.get("count", 1)

        # 根据特征字符串查到对应的规则（分数、级别）
        rule = patterns[pattern]
        # 这条告警对总风险分的贡献 = 单次分数 × min(命中次数, CAP)
        # min(count, CAP) 把命中次数封顶到 CAP
        contribution = rule["score"] * min(count, CAP)

        # 如果该 IP 还没有分数记录，初始化
        if ip not in scores:
            scores[ip] = {
                "total_risk_score": 0,
                "max_severity": None
            }

        # 累加风险分
        scores[ip]["total_risk_score"] += contribution

        # 更新最高严重级别
        current = scores[ip]["max_severity"]
        # 如果当前没有级别，或者新级别比当前级别高，就更新
        if current is None or SEVERITY_ORDER[rule["severity"]] > SEVERITY_ORDER[current]:
            scores[ip]["max_severity"] = rule["severity"]

    return scores

def generate_report(alerts, ip_count, threshold, profiles, not_found):
    """
    生成最终的安全分析报告。
    :param alerts: 告警列表
    :param ip_count: 所有 IP 的访问次数统计
    :param threshold: 高流量 IP 的访问次数阈值
    :param profiles: 所有 IP 的完整画像
    :param not_found: 每个 IP 的 404 次数统计
    :return: 报告字典
    """
    report = {
        "alerts": alerts,                          # 原始告警列表
        "suspicious_ips": [],                      # 可疑 IP 列表（有风险分的）
        "attacks": [],                             # 按 (IP, pattern) 聚合的攻击统计
        "high_volume_ips": [],                     # 高流量 IP 列表
        "scan_suspects": [],                       # 疑似扫描 IP 列表
        "ip_profiles": profiles                    # 所有 IP 的画像
    }

    # 按 IP + pattern 聚合真实攻击次数
    attack_stats = {}
    for alert in alerts:
        key = (alert["ip"], alert["pattern"])      # 用 IP 和特征组成唯一键
        count = alert.get("count", 1)

        # 如果这个 (IP, pattern) 组合第一次出现，初始化统计项
        if key not in attack_stats:
            attack_stats[key] = {
                "ip": alert["ip"],
                "pattern": alert["pattern"],
                "level": patterns[alert["pattern"]]["severity"],
                "type": patterns[alert["pattern"]]["type"],
                "count": 0
            }
        # 累加次数
        attack_stats[key]["count"] += count

    # 把每个聚合项的风险分算出来，加入报告
    for item in attack_stats.values():
        # 风险分 = min(次数, CAP) × 单次分数
        item["risk_score"] = min(item["count"], CAP) * patterns[item["pattern"]]["score"]
        report["attacks"].append(item)

    # attacks 按风险分从高到低排序
    # key=lambda x: x["risk_score"] 表示按 risk_score 字段排序
    # reverse=True 表示降序
    report["attacks"].sort(key=lambda x: x["risk_score"], reverse=True)

    # 筛选高流量 IP：访问次数 >= 阈值
    for ip, count in ip_count.items():
        if count >= threshold:
            report["high_volume_ips"].append({
                "ip": ip,
                "count": count
            })
    # 高流量 IP 按访问次数从高到低排序
    report["high_volume_ips"].sort(key=lambda x: x["count"], reverse=True)

    # 筛选可疑 IP：总风险分 > 0
    for ip, p in profiles.items():
        if p["total_risk_score"] > 0:
            report["suspicious_ips"].append({
                "ip": ip,
                "total_risk_score": p["total_risk_score"]
            })
    # 可疑 IP 按风险分从高到低排序
    report["suspicious_ips"].sort(key=lambda x: x["total_risk_score"], reverse=True)

    # 筛选疑似扫描 IP：404 次数 >= SCAN_THRESHOLD
    for ip, count404 in not_found.items():
        if count404 >= SCAN_THRESHOLD:
            report["scan_suspects"].append({
                "ip": ip,
                "not_found_404": count404
            })
    # 疑似扫描 IP 按 404 次数从高到低排序
    report["scan_suspects"].sort(key=lambda x: x["not_found_404"], reverse=True)

    return report

def analyze_log(log_file):
    """
    分析日志文件的主流程：逐行解析、归一化、检测攻击、聚合告警。
    :param log_file: 日志文件路径
    :return: (ips, alerts, not_found)
             - ips: 所有请求的 IP 列表
             - alerts: 聚合后的告警列表
             - not_found: 每个 IP 的 404 次数统计
    """
    ips = []                  # 存储所有请求的 IP（每个请求一条，可能重复）
    alert_dict = {}           # 按 (ip, pattern, status) 聚合告警的字典
    not_found = Counter()     # 统计每个 IP 的 404 次数

    with open(log_file, 'r') as f:
        for line in f:
            # 解析这一行日志
            log_data = parse_nginx_log(line)

            # 解析失败就跳过这行，打印提示
            if log_data is None:
                print(f"解析日志失败: {line.strip()}")
                continue

            # 对 URL 做归一化（解码、去注释）
            log_data = normalize_log(log_data)

            # 记录 IP
            ip = log_data["ip"]
            ips.append(ip)

            # 统计 404
            if log_data["status"] == 404:
                not_found[ip] += 1

            # 检测这一行是否命中攻击特征
            new_alerts = detect_attacks(log_data, line)

            for alert in new_alerts:
                # 用 IP + pattern + status 作为聚合键
                # 这样相同 IP 对相同特征发起的相同状态码请求会合并统计
                key = (alert["ip"], alert["pattern"], alert["status"])

                if key not in alert_dict:
                    # 第一次出现，保存完整信息，count 初始为 1
                    alert_dict[key] = {
                        "ip": alert["ip"],
                        "pattern": alert["pattern"],
                        "level": alert["level"],
                        "type": alert["type"],
                        "url": alert["url"],
                        "status": alert["status"],
                        "timestamp": alert["timestamp"],    # 首次出现时间
                        "last_seen": alert["timestamp"],    # 最后出现时间（初始同首次）
                        "line": alert["line"],
                        "count": 1
                    }
                else:
                    # 已存在，只增加次数并更新最后出现时间
                    alert_dict[key]["count"] += 1
                    alert_dict[key]["last_seen"] = alert["timestamp"]

    # 把聚合字典转成列表，后面处理更方便
    alerts = list(alert_dict.values())

    return ips, alerts, not_found

def process_log(log_path, threshold=5, output_file="report.json", enable_ai=False):
    # 分析日志，得到 IP 列表、告警列表、404 统计
        ips, alerts, not_found = analyze_log(log_path)

        # 统计每个 IP 的访问次数
        ip_count = count_ips(ips)

        # 统计每个 IP 的攻击次数
        attack_count = count_attacks_by_ip(alerts)

        # 构建每个 IP 的行为画像
        behavior = build_ip_behavior(ip_count, attack_count, alerts)

        # 统计每个 IP 的攻击类型
        attack_types = get_attack_types_by_ip(alerts)

        # 计算每个 IP 的风险分数
        scores = build_ip_scores(alerts)

        # 合并成完整的 IP 画像
        profiles = build_ip_profile(behavior, attack_types, scores)

        print("===== 开始生成报告 =====")
        # 生成最终报告
        report = generate_report(alerts, ip_count, threshold, profiles, not_found)

        # 把报告写入 JSON 文件
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=4)

        print(f"报告已保存到 {output_file}")

        # 打印统计摘要
        print(f"共分析 {len(ips)} 条请求, {len(alerts)} 条警告, {len(scores)} 个攻击IP")

        if enable_ai:
            print("\n===== 正在启动 AI 研判与事实校验 =====")
            ai_result = run_ai_analysis(report)

            if ai_result:
                with open("ai_result.json", "w", encoding="utf-8") as f:
                    json.dump(ai_result, f, ensure_ascii=False, indent=2)
                    
                print("\n===== 正在生成最终 Markdown 报告 =====")
                generate_markdown_report(report, ai_result, output_file="security_report.md")

        return report

def main():
    """
    主函数：解析命令行参数、运行分析、生成报告并写入文件。
    """
    # 创建命令行参数解析器
    parser = argparse.ArgumentParser(
        description="安全日志分析工具"
    )
    # 添加 -l/--log 参数：日志文件路径，必填
    parser.add_argument(
        "-l",
        "--log",
        required=True,
        help="日志文件路径"
    )
    # 添加 -t/--threshold 参数：可疑 IP 访问次数阈值，必填，整数类型
    parser.add_argument(
        "-t",
        "--threshold",
        required=True,
        type=int,
        help="可疑IP访问次数阈值"
    )
    # 添加 -o/--output 参数：报告输出路径，默认为 report.json
    parser.add_argument(
        "-o",
        "--output",
        default="report.json",
        help="报告输出文件路径"
    )
    # 【新增】添加一个开关参数 --ai
    parser.add_argument(
        "--ai",
        action="store_true",  #只要命令行里输入了 --ai，这个变量的值就是 True；没输就是 False
        help="是否调用大模型进行智能研判并生成最终报告"
    )

    # 解析命令行参数
    args = parser.parse_args()

    try:
        print("===== 开始全自动安全分析 =====")
        process_log(args.log, threshold=args.threshold, output_file=args.output, enable_ai=args.ai)
        print("===== 分析成功完成！ =====")

    except FileNotFoundError:
        # 如果日志文件不存在，提示用户
        print(f"日志文件 {args.log} 不存在！")


if __name__ == "__main__":
    main()
