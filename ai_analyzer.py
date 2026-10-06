# 导入 Python 内置模块 json，用于读写 JSON 文件和解析 JSON 字符串
import json
# 从 openai 库导入 OpenAI 客户端类，用来调用大模型 API
from openai import OpenAI
# 导入 os 模块，用于读取环境变量（API密钥存在环境变量里）
import os
# 导入 time 模块，用于重试时的等待（time.sleep）
import time

def get_ai_client():
    """获取 OpenAI 客户端对象，如果没配置密钥则报错"""
    api_key = os.getenv("OPENROUTER_API_KEY")

    if not api_key:
        raise RuntimeError("没有找到 OPENROUTER_API_KEY，请先配置OpenRouter API密钥")
    
    return OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key
    )

def analyze_with_ai(report, previous_errors=None):
    """
    使用 OpenRouter API 分析安全日志报告，返回分析结果。
    :param report: 安全日志报告（Python 字典），包含 alerts、ip_profiles 等数据
    :param previous_errors: 上一次校验失败的错误列表，用于让 AI 修正重答。首次调用为 None。
    :return: 包含 AI 分析结果的 Python 字典
    """
    # 获取 OpenAI 客户端对象
    client = get_ai_client()
    
    # 复制一份 report，避免直接修改原始 report
    # dict(report) 是浅拷贝，顶层键值对是新的，但子对象仍共享
    report_for_prompt = dict(report)

    # 为每个 alert 添加 alert_id 字段（alert 在数组中的下标，从 0 开始）
    # 这样 AI 引用证据时用 alert_id 就能定位到具体告警，也方便后续校验
    # {**alert, "alert_id": i} 意思是：把 alert 字典拆开，再加上 alert_id 字段
    # enumerate(report["alerts"]) 同时拿到下标 i 和告警内容 alert
    report_for_prompt["alerts"] = [
        {**alert, "alert_id": i}
        for i, alert in enumerate(report["alerts"])
    ]
    # 把带 alert_id 的报告转成格式化的 JSON 字符串
    # ensure_ascii=False 保留中文原文（否则中文会变成 \uXXXX 转义码）
    # indent=2 让 JSON 有 2 空格缩进，方便 AI 和人阅读
    report_text = json.dumps(
        report_for_prompt,
        ensure_ascii=False,
        indent=2
    )

    # retry_feedback 用于在重试时，把上一次的错误反馈给 AI，让它修正
    # 默认是空字符串，即首次调用时不带反馈
    retry_feedback = ""

    # 如果有上一次的错误（说明之前分析没通过校验），就拼接一段反馈文字
    if previous_errors:
        # f""" 是多行 f-string，{json.dumps(...)} 会把错误列表转成 JSON 字符串嵌进去
        retry_feedback = f"""
    ## 上一次输出未通过事实校验

    你上一次返回的 JSON 没有通过 Python 事实校验。

    具体错误：
    {json.dumps(previous_errors, ensure_ascii=False, indent=2)}

    请根据这些错误重新检查安全报告，并重新生成完整 JSON。

    要求：
    1. 修正上述错误。
    2. 仍然严格依据安全报告中的事实。
    3. 必须完整覆盖所有可疑 IP。
    4. evidence 必须能够覆盖对应 attack_count。
    5. 只返回修正后的合法 JSON，不要解释。
    """

    # 构造发送给 AI 的完整提示词（prompt）
    # f""" 是多行 f-string，{retry_feedback}、{report_text} 会被变量值替换
    # 注意：JSON 里的花括号必须写成 {{ }} 双写，因为 f-string 会把单层 {} 当成变量占位符
    prompt = f"""
    {retry_feedback}
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
    3. 没有证据支撑的结论只能写"推测/可能/疑似"，不能写成事实。
    4. 证据不足时，必须明确写"证据不足"。
    5. 除非报告中有足够证据支持自动处置，否则不要建议直接封禁 IP。
    6. assessment、reason 中提到的攻击类型、HTTP 状态码、攻击次数等，必须能在 evidence 对应的 alerts 记录或事实字段中找到对应。
    7. evidence 不是"代表性证据"，而是事实覆盖证据。对于每个 finding，evidence 必须覆盖该 IP 的全部攻击次数；不得为了简洁只选择部分 alert。

    ## 输出格式
    你必须只返回一个合法 JSON 对象，不输出 Markdown、不输出 JSON 之外的任何文字。

    顶层字段：
    - priority_ip（string）：最值得优先调查的 IP。选择依据：综合比较 total_risk_score（越高越优先）、attack_count（越多越优先）、attack_type_count（越多越优先）。必须取自 findings 中出现过的 IP。若报告中不存在任何 total_risk_score > 0 的 IP，则填空字符串 ""。
    - priority_level（enum：HIGH / MEDIUM / LOW）：调查优先级，仅表示优先程度，不表示攻击是否成功。若无可疑 IP，填 LOW。
    - reason（string）：说明 priority_ip 为何最值得优先调查，必须引用至少两个报告事实。若无可疑 IP，则说明报告中未检测到 total_risk_score > 0 的可疑 IP。
    - findings（array）：必须完整覆盖 ip_profiles 中所有 total_risk_score > 0 的可疑 IP，既不得遗漏，也不得多报；不得包含 total_risk_score = 0 的 IP。若不存在可疑 IP，返回空数组 []。

    每个 finding 对象字段：
    - ip（string）
    - assessment（string）：用完整句子描述该 IP 的安全行为，必须回答"发生了什么、有什么证据、为什么值得关注"，必须引用至少两个报告中的具体事实（可引用：攻击次数、攻击率、攻击类型、攻击时间跨度、攻击频率、严重级别、风险分数）。不得只返回 high/medium/low 等标签。不得声称攻击成功、数据泄露、凭据窃取或系统被攻破，除非报告明确提供了这些证据；若证据不足，必须写"证据不足"或"可能/疑似"。
    - confidence（enum：HIGH / MEDIUM / LOW）：对 assessment 判断本身的置信程度，不是对攻击成功的置信程度。
    - attack_count（integer）、request_count（integer）、attack_rate（number）、attack_time_span（number）、total_risk_score（integer）：事实字段，必须逐字复制自 ip_profiles[ip] 的同名字段，禁止计算、估算、四舍五入或推断，数值必须与报告完全一致。
    - claimed_attack_types（string 数组）：该 IP 涉及的攻击类型名称列表，每个 finding 必须包含此字段。名称必须取自报告中实际出现的攻击类型（ip_profiles 的 attack_types 或 alerts 的 type/pattern），必须与 assessment 描述一致，不得编造报告中不存在的类型。
    - evidence（array）：必须覆盖支持 assessment 的全部相关攻击告警。
    每条 evidence 只含一个字段 alert_id（integer），取值为该告警在 alerts 数组中的下标。
    alert_id 必须对应当前 IP 的实际告警记录，不得编造不存在的 alert_id。
    不要只选择每种攻击类型的一条代表性 alert。
    必须选择足够多的 alert，使这些 alert 的 count 总和等于当前 finding 的 attack_count。
    例如，如果 attack_count=10，则 evidence 对应的所有 alert 的 count 之和必须恰好为 10。
    assessment 中引用的攻击类型、攻击特征和 HTTP 状态码，必须能够从这些 alert_id 对应的 alerts 记录中得到支持。

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
        "claimed_attack_types": ["SQL注入"],
        "evidence": [
            {{ "alert_id": 0 }}
        ]
        }}
    ]
    }}

    ## 安全报告
    {report_text}
    """

    # 调用大模型 API 发起一次聊天请求
    # client.chat.completions.create 是 OpenAI SDK 提供的方法
    response = client.chat.completions.create(
        # model="openrouter/free" 表示使用 OpenRouter 提供的免费模型池
        model="openrouter/free",
        # extra_body 是 OpenRouter 特有的参数，指定具体使用哪几个免费模型
        # OpenRouter 会按顺序尝试这些模型，哪个可用就用哪个
        extra_body={
            "models": [
                "minimax/minimax-m3:free",
                "nex-agi/nex-n2-pro:free"
            ]
        },
        # messages 是对话消息列表，这里只有一条 user 消息，内容是上面构造的 prompt
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        # response_format 要求 AI 按 JSON Schema 结构化输出
        # type="json_schema" 指定使用 JSON Schema 模式
        # strict=True 要求 AI 严格遵守 schema 定义的字段
        response_format={
            "type": "json_schema",
            "json_schema": {
                "name": "security_analysis",  # schema 的名称标识
                "strict": True,               # 严格模式，字段必须和 schema 完全一致
                # 下面是 schema 定义，描述返回 JSON 的结构
                "schema": {
                    "type": "object",  # 顶层是一个对象（字典）
                    # properties 定义对象里有哪些字段
                    "properties": {
                        "priority_ip": {
                            "type": "string"
                        },
                        "priority_level": {
                            "type": "string",
                            "enum": [  # enum 限制取值只能是这三个之一
                                "HIGH",
                                "MEDIUM",
                                "LOW"
                            ]
                        },
                        "reason": {
                            "type": "string"
                        },
                        "findings": {
                            "type": "array",  # findings 是一个数组（列表）
                            "items": {  # 数组里每个元素的结构
                                "type": "object",
                                "properties": {
                                    "ip": {"type": "string"},
                                    "assessment": {"type": "string"},
                                    "confidence": {
                                        "type": "string",
                                        "enum": ["HIGH", "MEDIUM", "LOW"]
                                    },
                                    "attack_count": {"type": "integer"},
                                    "request_count": {"type": "integer"},
                                    "attack_rate": {"type": "number"},
                                    "attack_time_span": {"type": "number"},
                                    "total_risk_score": {"type": "integer"},
                                    "claimed_attack_types": {
                                        "type": "array",
                                        "items": {"type": "string"}
                                    },
                                    "evidence": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "alert_id": {"type": "integer"}
                                            },
                                            # required 表示这个字段必须出现
                                            "required": ["alert_id"],
                                            # additionalProperties=False 表示不允许多余字段
                                            "additionalProperties": False
                                        }
                                    }
                                },
                                # finding 对象必须包含以下所有字段
                                "required": [
                                    "ip",
                                    "attack_count",
                                    "request_count",
                                    "attack_rate",
                                    "attack_time_span",
                                    "total_risk_score",
                                    "claimed_attack_types",
                                    "assessment",
                                    "confidence",
                                    "evidence"
                                ],
                                "additionalProperties": False
                            }
                        }
                    },
                    # 顶层对象必须包含以下四个字段
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
    # 打印实际使用的模型名称（OpenRouter 可能从候选模型池里挑了一个）
    print("本次实际使用模型：", response.model)

    # 取出 AI 返回的文本内容
    # choices[0] 表示取第一条回复（AI 可能返回多条候选，这里只要第一条）
    # message.content 是回复的文本内容
    answer = response.choices[0].message.content
    # 尝试把 AI 返回的字符串解析成 Python 字典
    try:
        result = json.loads(answer)
    except json.JSONDecodeError:
        # 如果解析失败（AI 返回的不是合法 JSON），打印原始内容并抛出 ValueError
        print("AI 返回的内容不是合法 JSON:")
        print(answer)
        # raise ValueError 让上层函数（run_ai_analysis）捕获这个异常并触发重试
        raise ValueError(f"AI 返回的内容不是合法 JSON")

    # 解析成功，返回 Python 字典
    return result


def validate_ai_result(result, report):
    """
    校验 OpenRouter API 分析结果是否与安全日志报告一致。
    :param result: AI 返回的分析结果（Python 字典），包含 findings 等字段
    :param report: 安全日志报告（Python 字典），是事实来源
    :return: 一个字典，包含两个字段：
             - passed: 布尔值，表示校验是否通过
             - errors: 字符串列表，所有校验失败的错误信息（方便反馈给 AI 重试）
    """
    # 校验是否通过的标志，初始为 True，发现任何错误就改成 False
    validation_passed = True
    # 收集所有错误信息的列表
    errors = []

    # 提取报告中所有"可疑 IP"（total_risk_score > 0 的 IP）
    # 用集合 comprehension 生成集合，集合的特点是元素唯一、无序
    expected_ips = {
        ip
        for ip, profile in report["ip_profiles"].items()
        if profile["total_risk_score"] > 0
    }

    # 提取 AI 返回的 findings 中实际出现的 IP，同样用集合
    actual_ips = {
        finding["ip"]
        for finding in result["findings"]
    }

    # 集合减法：expected_ips - actual_ips = 报告里有、但 AI 没报的 IP（漏报）
    missing_ips = expected_ips - actual_ips

    # 如果有漏报的 IP，记录错误
    if missing_ips:
        # sorted(missing_ips) 把集合排序后转成列表，让输出顺序固定、易读
        message = f"AI 漏报可疑 IP: {sorted(missing_ips)}"
        print(message)
        errors.append(message)
        validation_passed = False

    # 逐个校验 AI 返回的每个 finding
    for finding in result["findings"]:
        # 取出当前 finding 的 IP
        ip = finding["ip"]
        # 从报告中查这个 IP 的画像数据
        # .get(ip) 如果 IP 不存在会返回 None，不会抛异常
        profile = report["ip_profiles"].get(ip)

        # 如果报告里根本没有这个 IP，说明 AI 编造了一个不存在的 IP
        if not profile:
            message = f"警告：AI 返回了报告中不存在的 IP: {ip}"
            print(message)
            errors.append(message)
            validation_passed = False
            # continue 跳过这个 finding 后续的校验，因为没有 profile 没法比
            continue

        # 校验 5 个事实字段是否和报告里的完全一致
        # 要求逐字复制，所以用 != 严格比较（不做约等于）
        for field in ("attack_count", "request_count", "attack_rate", "attack_time_span", "total_risk_score"):
            if finding[field] != profile.get(field):
                message = f"{ip} {field} 检验失败"
                print(message)
                errors.append(message)
                validation_passed = False
                continue

        # 初始化两个累加变量，用于校验 evidence
        # evidence_attack_count: evidence 中所有 alert 的攻击次数总和
        # evidence_attack_types: evidence 中出现过的攻击类型集合
        evidence_attack_count = 0
        evidence_attack_types = set()

        # 遍历当前 finding 的所有 evidence
        for evidence in finding["evidence"]:
            # 取出 evidence 引用的 alert_id
            alert_id = evidence["alert_id"]

            # 检查 alert_id 是否越界（小于 0 或大于等于 alerts 数组长度）
            if alert_id < 0 or alert_id >= len(report["alerts"]):
                message = f"{ip} evidence 检验失败：不存在的alert_id={alert_id}"
                print(message)
                errors.append(message)
                validation_passed = False
                continue

            # 根据 alert_id 取出对应的告警记录
            alert = report["alerts"][alert_id]

            # 检查这条告警是不是属于当前这个 IP
            # 如果 alert 的 IP 和 finding 的 IP 不一致，说明 AI 把别人的告警张冠李戴了
            if alert["ip"] != ip:
                message = f"{ip} evidence 校验失败：alert_id={alert_id} 不属于该 IP"
                print(message)
                errors.append(message)
                validation_passed = False
                continue

            # 累加这条告警的攻击次数（count 字段，没有则默认 1）
            # alert.get("count", 1) 意思是：取 count 字段，如果不存在就用 1
            evidence_attack_count += alert.get("count", 1)
            # 把这条告警的攻击类型加入集合（集合自动去重）
            evidence_attack_types.add(alert["type"])

        # 校验 evidence 的攻击次数总和是否等于 AI 声称的 attack_count
        # 这是"证据必须完整覆盖"的核心校验
        if evidence_attack_count != finding["attack_count"]:
            message = f"{ip} evidence 攻击次数校验失败：证据总次数={evidence_attack_count},AI返回attack_count={finding['attack_count']}"
            print(message)
            errors.append(message)
            validation_passed = False

        # 校验 AI 声称的每个攻击类型，是否都能在 evidence 中找到对应
        for attack_type in finding["claimed_attack_types"]:
            if attack_type not in evidence_attack_types:
                message = f"{ip} evidence 攻击类型校验失败：AI声称 {attack_type}但 evidence 中不存在"
                print(message)
                errors.append(message)
                validation_passed = False

    # 返回校验结果，包含是否通过和所有错误信息
    return {
        "passed": validation_passed,
        "errors": errors
    }


def run_ai_analysis(report, max_attempts=3):
    """
    运行 OpenRouter API 安全分析，带重试机制。
    如果 AI 返回的结果校验失败，会把错误反馈给 AI 让它修正，最多重试 max_attempts 次。
    :param report: 安全日志报告（Python 字典）
    :param max_attempts: 最大尝试次数，默认 3 次
    :return: 校验通过的 AI 分析结果（Python 字典）；如果重试后仍失败则返回 None
    """
    # 收集所有错误信息，用于在重试时反馈给 AI
    errors = []

    # 循环尝试，从第 1 次到第 max_attempts 次
    # range(1, max_attempts + 1) 生成 1, 2, 3（当 max_attempts=3 时）
    for attempt in range(1, max_attempts + 1):
        print(f"\n========== AI 第 {attempt} 次分析 ==========")

        # 尝试调用 AI 分析
        try:
            # previous_errors=errors 把之前的错误传给 AI，让它修正
            result = analyze_with_ai(report, previous_errors=errors)

        # 如果 AI 返回的内容不是合法 JSON，analyze_with_ai 会抛出 ValueError
        except ValueError as e:
            # str(e) 把异常转成错误信息字符串
            error_message = str(e)

            print("AI 返回结果格式错误")
            print(error_message)

            # 错误信息覆盖 errors 列表（这次的错误只有"格式错误"这一条）
            errors = [error_message]

            # 如果还没到最大重试次数，等待后继续下一次循环
            if attempt < max_attempts:
                # 指数退避：第1次等1秒，第2次等2秒，第3次等4秒
                # 2 ** (attempt - 1) 即 2 的 (attempt-1) 次方
                wait_time = 2 ** (attempt - 1)

                print(f"{wait_time} 秒后进行第 {attempt + 1} 次分析...")

                # time.sleep 让程序暂停指定秒数
                time.sleep(wait_time)
                # continue 跳到下一次循环（重试）
                continue

            # 已经到最大重试次数，放弃
            print("已达最大重试次数，不保存 AI 分析结果。")
            return None

        # 走到这里说明 AI 返回了合法 JSON，打印分析结果
        print("========== AI 安全分析结果 ==========")
        print(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2
            )
        )

        # 对 AI 结果做事实校验
        validation_result = validate_ai_result(result, report)

        print("========== AI 事实校验 ==========")

        # 如果校验通过，直接返回结果，不再重试
        if validation_result["passed"]:
            print("通过：AI 返回的结构化事实与 Python 报告一致")
            return result

        # 校验失败，把错误信息存下来，下次重试时反馈给 AI
        errors = validation_result["errors"]

        print("失败：AI 返回的结构化事实与 Python 报告不一致")

        # 逐条打印所有错误
        for error in errors:
            print(f"- {error}")

        # 如果还没到最大重试次数，等待后重试
        if attempt < max_attempts:
            wait_time = 2 ** (attempt - 1)

            print(f"{wait_time} 秒后进行第 {attempt + 1} 次分析...")

            time.sleep(wait_time)

        # 已经到最大重试次数，放弃
        else:
            print("已达最大重试次数。")
            return None


def main():
    """
    主函数：运行 AI 分析，并在成功时把结果保存到 ai_result.json。
    """
    try:
        # 读取 JSON 报告文件 report.json
        with open("report.json", "r", encoding="utf-8") as f:
            report = json.load(f)
    except FileNotFoundError:
        print("错误：未找到 report.json，请先运行main.py 生成报告!")
        return
    # 调用 run_ai_analysis 获取校验通过的 AI 分析结果
    # 内部会自动重试，最多 3 次；如果都失败返回 None
    result = run_ai_analysis(report)

    # 如果结果是 None，说明重试都失败了，不保存
    if result is None:
        print("AI 最终分析失败，不保存结果。")
        # return 直接结束函数，不执行后面的保存代码
        return

    # 校验通过，把结果写入 ai_result.json
    # "w" 写入模式（不存在则新建，存在则覆盖）
    # json.dump 把 Python 字典直接写入文件对象 f
    with open("ai_result.json", "w", encoding="utf-8") as f:
        json.dump(
            result,
            f,
            ensure_ascii=False,  # 保留中文
            indent=2             # 2 空格缩进，格式化输出
        )

    print("AI 分析结果已保存到 ai_result.json")


# 这个判断确保只有直接运行 ai_analyzer.py 时才执行 main()
# 如果其他文件 import ai_analyzer，不会触发 main()
if __name__ == "__main__":
    main()
