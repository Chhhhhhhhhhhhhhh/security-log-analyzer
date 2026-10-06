import json
from ai_analyzer import validate_ai_result, run_ai_analysis

try:
    with open("test_report.json", "r", encoding="utf-8") as f:
        report = json.load(f)
except FileNotFoundError: 
    with open("report.json", "r", encoding="utf-8") as f:
        report = json.load(f)

correct_result = {
    "findings": [
        {
            "ip": "192.168.153.133",
            "attack_count": 10,
            "request_count": 49,
            "attack_rate": 0.20408163265306123,
            "attack_time_span": 781.0,
            "total_risk_score": 85,
            "claimed_attack_types": [
                "SQL_Injection",
                "XSS",
                "Path_Traversal"
            ],
            "evidence": [
                {"alert_id": 0},
                {"alert_id": 1},
                {"alert_id": 2},
                {"alert_id": 3},
                {"alert_id": 4},
                {"alert_id": 6},
                {"alert_id": 7}
            ]
        },
        {
            "ip": "192.168.153.132",
            "attack_count": 1,
            "request_count": 14,
            "attack_rate": 0.07142857142857142,
            "attack_time_span": 0.0,
            "total_risk_score": 5,
            "claimed_attack_types": [
                "XSS"
            ],
            "evidence": [
                {"alert_id": 5}
            ]
        },
        {
            "ip": "192.168.153.1",
            "attack_count": 2,
            "request_count": 16,
            "attack_rate": 0.125,
            "attack_time_span": 14.0,
            "total_risk_score": 20,
            "claimed_attack_types": [
                "Path_Traversal"
            ],
            "evidence": [
                {"alert_id": 8},
                {"alert_id": 9}
            ]
        }
    ]
}
wrong_result = {
    "findings": [
        {
            "ip": "192.168.153.132",
            "attack_count": 999,
            "request_count": 14,
            "attack_rate": 0.07142857142857142,
            "attack_time_span": 0.0,
            "total_risk_score": 5,
            "claimed_attack_types": ["XSS"],
            "evidence": [
                {"alert_id": 5}
            ]
        }
    ]
}
def test_invalid_alert_id():
    invalid_alert_result = {
        "findings": [
            {
                "ip": "192.168.153.132",
                "attack_count": 1,
                "request_count": 14,
                "attack_rate": 0.07142857142857142,
                "attack_time_span": 0.0,
                "total_risk_score": 5,
                "claimed_attack_types": ["XSS"],
                "evidence": [
                    {"alert_id": 999}
                ]
            }
        ]
    }

    assert validate_ai_result(invalid_alert_result, report)["passed"] is False

def test_alert_from_wrong_ip():
    wrong_ip_result = {
        "findings": [
            {
                "ip": "192.168.153.132",
                "attack_count": 1,
                "request_count": 14,
                "attack_rate": 0.07142857142857142,
                "attack_time_span": 0.0,
                "total_risk_score": 5,
                "claimed_attack_types": ["XSS"],
                "evidence": [
                    {"alert_id": 0}
                ]
            }
        ]
    }

    assert validate_ai_result(wrong_ip_result, report)["passed"] is False

def test_wrong_attack_type():
    wrong_attack_type_result = {
        "findings": [
            {
                "ip": "192.168.153.132",
                "attack_count": 1,
                "request_count": 14,
                "attack_rate": 0.07142857142857142,
                "attack_time_span": 0.0,
                "total_risk_score": 5,
                "claimed_attack_types": ["SQL_Injection"],
                "evidence": [
                    {"alert_id": 5}
                ]
            }
        ]
    }

    assert validate_ai_result(wrong_attack_type_result, report)["passed"] is False

def test_incomplete_evidence():
    incomplete_result = {
        "findings": [
            {
                "ip": "192.168.153.133",
                "attack_count": 10,
                "request_count": 49,
                "attack_rate": 0.20408163265306123,
                "attack_time_span": 781.0,
                "total_risk_score": 85,
                "claimed_attack_types": [
                    "SQL_Injection",
                    "XSS",
                    "Path_Traversal"
                ],
                "evidence": [
                    {"alert_id": 0},
                    {"alert_id": 1}
                ]
            }
        ]
    }

    assert validate_ai_result(incomplete_result, report)["passed"] is False

def test_missing_suspicious_ip():
    missing_result = {
        "findings": [
            {
                "ip": "192.168.153.133",
                "attack_count": 10,
                "request_count": 49,
                "attack_rate": 0.20408163265306123,
                "attack_time_span": 781.0,
                "total_risk_score": 85,
                "claimed_attack_types": [
                    "SQL_Injection",
                    "XSS",
                    "Path_Traversal"
                ],
                "evidence": [
                    {"alert_id": 0},
                    {"alert_id": 1},
                    {"alert_id": 2},
                    {"alert_id": 3},
                    {"alert_id": 4},
                    {"alert_id": 6},
                    {"alert_id": 7}
                ]
            }
        ]
    }

    assert validate_ai_result(missing_result, report)["passed"] is False

def test_retry_success_after_failure(monkeypatch):
    call_count = 0

    def fake_analyze_with_ai(report, previous_errors=None):
        nonlocal call_count

        call_count += 1

        if call_count < 3:
            return {"findings": []}

        return correct_result

    # 把真正的 AI 调用替换成我们自己的假函数
    monkeypatch.setattr(
        "ai_analyzer.analyze_with_ai",
        fake_analyze_with_ai
    )

    # 测试时不真的等待 1 秒
    monkeypatch.setattr(
        "ai_analyzer.time.sleep",
        lambda seconds: None
    )

    result = run_ai_analysis(
        report,
        max_attempts=3
    )

    assert result == correct_result
    assert call_count == 3

def test_retry_exhausted(monkeypatch):
    call_count = 0

    def fake_analyze_with_ai(report, previous_errors=None):
        nonlocal call_count

        call_count += 1

        # 每一次都返回错误结果
        return {
            "findings": []
        }

    monkeypatch.setattr(
        "ai_analyzer.analyze_with_ai",
        fake_analyze_with_ai
    )

    monkeypatch.setattr(
        "ai_analyzer.time.sleep",
        lambda seconds: None
    )

    result = run_ai_analysis(
        report,
        max_attempts=3
    )

    assert result is None
    assert call_count == 3

def test_retry_after_invalid_json(monkeypatch):
    call_count = 0

    def fake_analyze_with_ai(report, previous_errors=None):
        nonlocal call_count

        call_count += 1

        if call_count == 1:
            raise ValueError("AI 返回的内容不是合法 JSON")

        return correct_result

    monkeypatch.setattr(
        "ai_analyzer.analyze_with_ai",
        fake_analyze_with_ai
    )

    monkeypatch.setattr(
        "ai_analyzer.time.sleep",
        lambda seconds: None
    )

    result = run_ai_analysis(
        report,
        max_attempts=3
    )

    assert result == correct_result
    assert call_count == 2

def test_correct_result():
    assert validate_ai_result(correct_result, report)["passed"] is True
def test_wrong_result():
    assert validate_ai_result(wrong_result, report)["passed"] is False
