import json

def generate_markdown_report(report, ai_result, output_file="security_report.md"):

    priority_ip = ai_result["priority_ip"]
    priority_level = ai_result["priority_level"]
    reason = ai_result["reason"]

    lines = []
    title = "# Security Analysis Report"
    findings = ai_result["findings"]


    for ip, profile in report["ip_profiles"].items():
        if profile["attack_count"] > 0:
            attack_types = ", ".join(profile["attack_types"])
            lines.append(f"## IP: {ip}")
            lines.append("")
            lines.append(f"- Attack Count: {profile['attack_count']}")
            lines.append(f"- IP Location: {profile['location']}")
            lines.append(f"- ISP: {profile['isp']}")
            lines.append(f"- Risk Score: {profile['total_risk_score']}")
            lines.append(f"- Max Severity: {profile['max_severity']}")
            lines.append(f"- Attack Types: {attack_types}")
            lines.append("")

            for finding in findings:
                if finding["ip"] == ip:
                    evidence = finding["evidence"]
                    evidence_lines = []
                    lines.append("### Evidence:")
                    
                    for item in evidence:
                        alert_id = item["alert_id"]
                        alert = report["alerts"][alert_id]
                        evidence_lines.append(f"- Alert ID: {alert_id}, Type: {alert['type']}, Pattern: {alert['pattern']}, Count: {alert['count']}, Status: {alert['status']}, Url: {alert['url']}, Timestamp: {alert['timestamp']}, Last Seen: {alert['last_seen']}")
                        
                    lines.extend(evidence_lines)
                    lines.append("")
                    lines.append(f"- AI confidence: {finding['confidence']}")
                    lines.append("")
                    lines.append(f"### AI Assessment:")
                    lines.append("")
                    lines.append(f"{finding['assessment']}")
                    break
            

    lines.insert(0, title)
    lines.insert(1, f"- Priority IP: {priority_ip}")
    lines.insert(2, f"- Priority Level: {priority_level}")
    lines.insert(3, f"- Reason: {reason}")

    lines.append("## 🚨 推荐应急处置措施 (Remediation)")
    lines.append("")

    if priority_ip:
        lines.append(f"**最高优先级拦截目标: ** '{priority_ip}' (等级: {priority_level})")
        lines.append("")
        
        lines.append("### 1. Linux 防火墙一键封禁命令 (iptables)")
        lines.append("```bash")
        lines.append(f"iptables -I INPUT -s {priority_ip} -j DROP")
        lines.append("```")
        lines.append("")

        lines.append("### 2. Nginx 黑名单配置 (添加到 server 块内)")
        lines.append("```nginx")
        lines.append(f"deny {priority_ip};")
        lines.append("```")
        lines.append("")
    else:
        lines.append("当前未检测到高危攻击 IP，无需执行紧急封禁。")
        lines.append("")

    report_text = "\n".join(lines)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report_text)

    print(f"安全分析报告已成功生成：{output_file}")
    return report_text

if __name__ == "__main__":
    try:
        with open("report.json", "r", encoding="utf-8") as f:
            report_data = json.load(f)
        with open("ai_result.json", "r", encoding="utf-8") as f:
            ai_data = json.load(f)
    except FileNotFoundError as e:
        print(f"错误：缺少必要的 Json 结果文件，无法生成报告（{e}）")
    
    else:
        generate_markdown_report(report_data, ai_data)
