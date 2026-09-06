from urllib import parse
from collections import Counter
import json
import argparse
import ipaddress
from datetime import datetime

patterns = {                             #定义一个字典，键为特征，值为等级和类型信息
    "union select": {
        "severity": "HIGH",
        "score": 10,
        "type": "SQL_Injection"
    },

    "' or '": {
        "severity": "HIGH",
        "score": 10,
        "type": "SQL_Injection"
    },

    "<script": {
        "severity": "MEDIUM",
        "score": 5,
        "type": "XSS"
    }
}
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

CAP = 10

SCAN_THRESHOLD = 3

def parse_nginx_log(line):
    """
    解析简单的日志格式：IP - METHOD URL HTTP/1.1 STATUS SIZE
    """
    parts = line.split('"')
    

    if len(parts) != 7:
        return None

    first_part = parts[0].strip()

    request_part = parts[1].strip()

    first_parts = first_part.split()


    if len(first_parts) != 5:
        return None

    ip = first_parts[0]

    if not is_valid_ip(ip):
        return None
    
    timestamp = " ".join(first_parts[3:5])


    request_parts = request_part.split()


    if len(request_parts) < 3:
        return None

    method = request_parts[0]

    url = " ".join(request_parts[1:-1])

    protocol = request_parts[-1]
    
    status_size = parts[2].split()
    if len(status_size) != 2:
        return None
   
    status = int(status_size[0])

    size = int(status_size[1]) if status_size[1] != '-' else 0

    referer = parts[3]

    user_agent = parts[5]

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
    检查IP地址是否有效，返回布尔值。
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def normalize_log(log_data):
    """
    对日志行进行归一化处理。
    """
    url = parse.unquote(log_data["url"])
    url = url.replace("/**/", "")

    log_data["url"] = url

    return log_data

def detect_attacks(log_data, line):
    """
    对归一化后的日志行进行攻击检测，返回所有匹配的攻击特征。
    """
    ip = log_data["ip"]
    url = log_data["url"]
    status = log_data["status"]

    alerts = []
    
    for pattern, level in patterns.items():
        if pattern in url.lower():
            alert = {
                "ip": ip,
                "pattern": pattern,
                "level": level["severity"],
                "type": level["type"],
                "url": url,
                "status": status,
                "timestamp": log_data["timestamp"],
                "line": line
            }
            alerts.append(alert)

    return alerts

def count_ips(ips):
    """
    统计所有IP地址的访问次数，返回一个字典。
    """
    ip_count = Counter(ips)

    return ip_count

def count_attacks_by_ip(alerts):
    """
    统计所有IP地址的攻击次数，返回一个字典。
    """
    attack_count = Counter(
        alert['ip']
        for alert in alerts
    )
    
    return attack_count

def build_ip_behavior(ip_count, attack_count, alerts):
    """
    构建IP地址的攻击行为，返回一个字典。
    """

    behavior = {}

    for ip, request_count in ip_count.items():
        attack = attack_count.get(ip, 0)

        ip_alerts =[
            alert for alert in alerts if alert["ip"] == ip
        ]

        if ip_alerts:
            times = [datetime.strptime(
                alert["timestamp"],
                "[%d/%b/%Y:%H:%M:%S %z]"
            )
            for alert in ip_alerts]

            attack_time_span = (max(times)-min(times)).total_seconds()
        else:
            attack_time_span = 0

        if attack_time_span > 0:
            attack_frequency = attack / max(attack_time_span, 1)
        else:
            attack_frequency = 0

        behavior[ip] = {
            "request_count": request_count,
            "attack_count": attack,
            "attack_rate": attack / request_count,
            "attack_time_span": attack_time_span,
            "attack_frequency": attack_frequency
        }

    return behavior

def get_attack_types_by_ip(alerts):
    """
    统计所有IP地址的攻击类型，返回一个字典。
    """
    attack_types = {}
    
    for alert in alerts:
        ip = alert["ip"]
        attack_type = alert["type"]

        if ip not in attack_types:
            attack_types[ip] = set()
        
        attack_types[ip].add(attack_type)

    return attack_types

def build_ip_profile(behavior, attack_types, scores):
    profiles = {}

    for ip, data in behavior.items():
        types = attack_types.get(ip, set())
        s = scores.get(ip, {})

        profiles[ip] = {
            "request_count": data["request_count"],
            "attack_count": data["attack_count"],
            "attack_rate": data["attack_rate"],
            "attack_types": list(types),
            "attack_type_count": len(types),
            "attack_time_span": data["attack_time_span"],
            "attack_frequency": data["attack_frequency"],
            "max_severity": s.get("max_severity"),
            "total_risk_score": s.get("total_risk_score", 0)
        }

    return profiles

def build_ip_scores(alerts):
    """
    计算每个IP的封顶风险总分和最高严重级别。
    """
    alert_count = Counter(
        (alert['ip'],alert['pattern'])
        for alert in alerts
    )

    scores = {}

    for (ip, pattern), count in alert_count.items():
        rule = patterns[pattern]
        contribution = rule["score"] * min(count, CAP)

        if ip not in scores:
            scores[ip] = {
                "total_risk_score": 0,
                "max_severity": None
            }
        
        scores[ip]["total_risk_score"] += contribution

        current = scores[ip]["max_severity"]
        if current is None or SEVERITY_ORDER[rule["severity"]] > SEVERITY_ORDER[current]:
            scores[ip]["max_severity"] = rule["severity"]
    
    return scores

def generate_report(alerts, ip_count, threshold, profiles, not_found):
    """
    生成攻击报告，包括可疑IP、攻击特征、攻击次数等信息。
    """
    report = {
        "alerts": alerts,
        "suspicious_ips": [],
        "attacks": [],
        "high_volume_ips": [],
        "scan_suspects": [],
        "ip_profiles": profiles
    }                           #定义一个空字典，用于存储所有攻击信息


    alert_count = Counter(              #统计所有攻击特征的出现次数
        (alert['ip'],alert['pattern'])
        for alert in alerts
    )

    for key, count in alert_count.items():     #遍历攻击键值对，打印攻击信息
        ip, pattern = key
        
        report["attacks"].append({
            "ip": ip,
            "pattern": pattern,
            "level": patterns[pattern]["severity"],
            "type": patterns[pattern]["type"],
            "count": count,
            "risk_score": min(count, CAP) * patterns[pattern]["score"]
        })
    report["attacks"].sort(key=lambda x: x["risk_score"], reverse=True)     #按风险分数排序，从高到低

    for ip, count in ip_count.items():
        if count >= threshold:                      #如果访问次数大于等于阈值，认为是可疑IP
            
            report["high_volume_ips"].append({
                "ip": ip,
                "count": count
            })
    report["high_volume_ips"].sort(key=lambda x: x["count"], reverse=True)     #按访问次数排序，从高到低
    
    for ip, p in profiles.items():
        if p["total_risk_score"] > 0:
            report["suspicious_ips"].append({
                "ip": ip,
                "total_risk_score": p["total_risk_score"]
            })

    report["suspicious_ips"].sort(key=lambda x: x["total_risk_score"], reverse=True)     #按风险分数排序，从高到低

    for ip, count404 in not_found.items():
        if count404 >= SCAN_THRESHOLD:
            report["scan_suspects"].append({
                "ip": ip,
                "not_found_404": count404
            })
    report["scan_suspects"].sort(key=lambda x: x["not_found_404"], reverse=True)      #按404错误次数排序，从高到低
    
    return report
    
def analyze_log(log_file):
    """
    分析日志文件，返回所有IP地址和匹配的攻击特征。
    """
    ips = []     #定义一个空列表，用于存储所有IP地址
    alerts = []              #定义一个空列表，用于存储所有告警信息
    not_found = Counter()

    with open(log_file, 'r') as f:     #打开日志文件，只读模式
        for line in f:
            log_data = parse_nginx_log(line)

            if  log_data is None:                        #如果日志解析失败，跳过该行
                print(f"解析日志失败: {line.strip()}")
                continue
            
            log_data = normalize_log(log_data)
            
            ip = log_data["ip"]

            ips.append(ip)
            if log_data["status"] == 404:
                not_found[ip] += 1
            new_alerts = detect_attacks(log_data, line)

            alerts.extend(new_alerts)

    return ips, alerts, not_found

def main():
    """
    主函数，用于处理命令行参数、调用分析函数、生成报告。
    """
    parser =argparse.ArgumentParser(
        description="安全日志分析工具"
    )
    parser.add_argument(
        "-l",
        "--log",
        required=True,
        help="日志文件路径"
    )
    parser.add_argument(
        "-t",
        "--threshold",
        required=True,
        type=int,
        help="可疑IP访问次数阈值"
    )
    parser.add_argument(
        "-o",
        "--output",
        default="report.json",
        help="报告输出文件路径"
    )


    args = parser.parse_args()



    try:
        ips, alerts, not_found = analyze_log(args.log)

        ip_count = count_ips(ips) 

        attack_count = count_attacks_by_ip(alerts)

        behavior = build_ip_behavior(ip_count, attack_count, alerts)

        attack_types = get_attack_types_by_ip(alerts)

        scores = build_ip_scores(alerts)
        
        profiles = build_ip_profile(behavior, attack_types, scores)
        
        print("===== 开始生成报告 =====")
        report = generate_report(alerts, ip_count, args.threshold, profiles, not_found)

        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=4)

        print(f"报告已保存到 {args.output}")

        print(f"共分析 {len(ips)} 条请求, {len(alerts)} 条警告, {len(scores)} 个攻击IP")
        
    except FileNotFoundError:
        print(f"日志文件 {args.log} 不存在！")
    

if __name__ == "__main__":
    main()