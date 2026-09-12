import json
from openai import OpenAI
import os

api_key = os.getenv("OPENROUTER_API_KEY")

if not api_key:
    raise RuntimeError(
        "没有找到 OPENROUTER_API_KEY，请先配置OpenRouter API密钥"
    )

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=api_key
)                                                            # 初始化 OpenAI 客户端

with open("report.json", "r", encoding="utf-8") as f:
    report = json.load(f)

report_for_prompt = dict(report)
report_for_prompt["alerts"] = [
    {**alert, "alert_id": i}
    for i, alert in enumerate(report["alerts"])
]
report_text = json.dumps(
    report_for_prompt,
    ensure_ascii=False,
    indent=2
)

prompt = f"""
你是一名网络安全分析师，需要分析下面由 Python 安全日志分析器生成的 JSON 报告。

## 报告结构说明
报告包含以下关键节点，事实字段来源不同，务必区分：
- alerts：按单条日志记录的告警数组，每条含 alert_id、ip、pattern、level、type、url、status、timestamp。alert_id 是该告警在数组中的下标，同一 IP 可能出现多条 alert。
- suspicious_ips：列出 total_risk_score > 0 的可疑 IP 及其风险分。
- attacks：按 (IP, pattern) 聚合的攻击统计，含 count、risk_score。
- ip_profiles：每个 IP 的完整画像，事实字段从这里取，包括：attack_count、request_count、attack_rate、attack_time_span、attack_frequency、total_risk_score、max_severity、attack_types、attack_type_count。

## 分析原则
1. 严格基于报告事实，不编造报告中不存在的信息。
2. 检测到攻击特征 ≠ 攻击成功；HTTP 200 仅代表请求被服务器接收，≠ 攻击成功。
3. 没有证据支撑的结论只能写“推测/可能/疑似”，不能写成事实。
4. 证据不足时，必须明确写“证据不足”。
5. 除非报告中有足够证据支持自动处置，否则不要建议直接封禁 IP。
6. assessment、reason 中提到的攻击类型、HTTP 状态码、攻击次数等，必须能在 evidence 对应的 alerts 记录或事实字段中找到对应。

## 输出格式
你必须只返回一个合法 JSON 对象，不输出 Markdown、不输出 JSON 之外的任何文字。

顶层字段：
- priority_ip（string）：最值得优先调查的 IP。选择依据：综合比较 total_risk_score（越高越优先）、attack_count（越多越优先）、attack_type_count（越多越优先）。
- priority_level（enum：HIGH / MEDIUM / LOW）：调查优先级，仅表示优先程度，不表示攻击是否成功。
- reason（string）：说明 priority_ip 为何最值得优先调查，必须引用至少两个报告事实。
- findings（array）：只包含 ip_profiles 中 total_risk_score > 0 的可疑 IP，不得包含 total_risk_score = 0 的 IP。

每个 finding 对象字段：
- ip（string）
- assessment（string）：用完整句子描述该 IP 的安全行为，必须回答“发生了什么、有什么证据、为什么值得关注”，必须引用至少两个报告中的具体事实（可引用：攻击次数、攻击率、攻击类型、攻击时间跨度、攻击频率、严重级别、风险分数）。不得只返回 high/medium/low 等标签。不得声称攻击成功、数据泄露、凭据窃取或系统被攻破，除非报告明确提供了这些证据；若证据不足，必须写“证据不足”或“可能/疑似”。
- confidence（enum：HIGH / MEDIUM / LOW）：对 assessment 判断本身的置信程度，不是对攻击成功的置信程度。
- attack_count（integer）、request_count（integer）、attack_rate（number）、attack_time_span（number）、total_risk_score（integer）：事实字段，必须逐字复制自 ip_profiles[ip] 的同名字段，禁止计算、估算、四舍五入或推断，数值必须与报告完全一致。
- evidence（array）：支持 assessment 的直接报告证据。每条 evidence 只含一个字段 alert_id（integer），取值为该告警在 alerts 数组中的下标。alert_id 必须对应当前 IP 的实际告警记录，不得编造不存在的 alert_id。assessment 中引用的攻击类型、攻击特征和 HTTP 状态码，必须能够从这些 alert_id 对应的 alerts 记录中得到支持。

## 输出示例（仅示范结构，具体数值必须按报告实际填写）
{{
  "priority_ip": "192.168.1.52",
  "priority_level": "HIGH",
  "reason": "192.168.1.52 的 total_risk_score=100 为全场最高，且 attack_count=12 显示集中性攻击行为，符合优先调查标准。",
  "findings": [
    {{
      "ip": "192.168.1.52",
      "assessment": "该 IP 在报告中发起 12 次 union select 类型的 SQL 注入，attack_rate=1.0 表示其全部请求均为攻击请求，total_risk_score=100 为全场最高。所有请求返回 HTTP 200，仅代表请求被服务器接收，不能据此推断注入成功；是否实际造成数据泄露，证据不足。",
      "confidence": "HIGH",
      "attack_count": 12,
      "request_count": 12,
      "attack_rate": 1.0,
      "attack_time_span": 0.0,
      "total_risk_score": 100,
      "evidence": [
        {{ "alert_id": 0 }}
      ]
    }}
  ]
}}

## 安全报告
{report_text}
"""

response = client.chat.completions.create(
    model="openrouter/free",
    messages=[
        {
            "role": "user",
            "content": prompt
        }
    ],
    response_format={
        "type": "json_schema",
        "json_schema": {
            "name": "security_analysis",
            "strict": True,
            "schema": {
                "type": "object",
                "properties": {
                    "priority_ip": {
                        "type": "string"
                    },
                    "priority_level": {
                        "type": "string",
                        "enum": [
                            "HIGH",
                            "MEDIUM",
                            "LOW"
                        ]
                    },
                    "reason": {
                        "type": "string"
                    },
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "ip": {
                                    "type": "string"
                                },
                                "assessment": {
                                    "type": "string"
                                },
                                "confidence": {
                                    "type": "string",
                                    "enum": [
                                        "HIGH",
                                        "MEDIUM",
                                        "LOW"
                                    ]
                                },
                                "attack_count": {
                                    "type": "integer"
                                },
                                "request_count": {
                                    "type": "integer"
                                },
                                "attack_rate": {
                                    "type": "number"
                                },
                                "attack_time_span": {
                                    "type": "number"
                                },
                                "total_risk_score": {
                                    "type": "integer"
                                },
                                "evidence": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "alert_id": {
                                                "type": "integer"
                                            }
                                        },
                                        "required": [
                                            "alert_id"
                                        ],
                                        "additionalProperties": False
                                    }
                                }
                            },
                            "required": [
                                "ip",
                                "attack_count",
                                "request_count",
                                "attack_rate",
                                "attack_time_span",
                                "total_risk_score",
                                "assessment",
                                "confidence",
                                "evidence"
                            ],
                            "additionalProperties": False
                        }
                    }
                },
                "required": [
                    "priority_ip",
                    "priority_level",
                    "reason",
                    "findings"
                ],
                "additionalProperties": False
            }
        }
    }
)

answer = response.choices[0].message.content

try:
    result = json.loads(answer)
except json.JSONDecodeError:
    print("AI 返回的内容不是合法 JSON:")
    print(answer)
    raise

print("========== AI 安全分析结果 ==========")
print(
    json.dumps(
        result,
        ensure_ascii=False,
        indent=2
    )
)

validation_passed = True

for finding in result["findings"]:
    ip = finding["ip"]
    profile = report["ip_profiles"].get(ip)

    if not profile:
        print(f"警告：AI 返回了报告中不存在的 IP: {ip}")
        validation_passed = False
        continue
    
    for field in ("attack_count", "request_count", "attack_rate", "attack_time_span", "total_risk_score"):
        if finding[field] != profile.get(field):
            print(f"{ip} {field} 检验失败")
            validation_passed = False
            continue

    for evidence in finding["evidence"]:
        alert_id = evidence["alert_id"]

        if alert_id < 0 or alert_id >= len(report["alerts"]):
            print(f"{ip} evidence 检验失败：不存在的alert_id={alert_id}")
            validation_passed = False
            continue

        alert = report["alerts"][alert_id]

        if alert["ip"] != ip:
            print(
                f"{ip} evidence 校验失败："
                f"alert_id={alert_id} 不属于该 IP"
            )
            validation_passed = False

print("========== AI 事实校验 ==========")

if validation_passed:
    print("通过：AI 返回的结构化事实与 Python 报告一致")
else:
    print("失败：AI 返回的结构化事实与 Python 报告不一致")
