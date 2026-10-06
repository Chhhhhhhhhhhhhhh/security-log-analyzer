import streamlit as st
import json
from main import process_log

st.set_page_config(page_title="安全日志分析 Agent", page_icon="🛡️", layout="wide")

st.title("🛡️ 智能安全日志分析与应急处置平台")
st.caption("基于【规则引擎 + 威胁情报 + LLM 事实校验】的自动化安全运营系统")

st.sidebar.header("⚙️ 任务控制台")
uploaded_file = st.sidebar.file_uploader("📂 拖入或选择 Nginx 日志文件", type=["log", "txt"])
threshold = st.sidebar.slider("🎯 高频异常访问阈值", min_value=1, max_value=50, value=5)
start_btn = st.sidebar.button("🚀 开始自动化研判")

if start_btn:
    if uploaded_file is None:
        st.sidebar.warning("⚠️ 请拖入或上传 Nginx 日志文件")
    else:
        with open("temp_uploaded.log", "wb") as f:
            f.write(uploaded_file.getbuffer())

        with st.sidebar.spinner("⏳ 正在分析日志并调用 AI 深度研判..."):
            process_log("temp_uploaded.log", threshold=threshold, enable_ai=True)

        st.sidebar.success("✅ 分析完成！")
        st.rerun()

# 读取我们的分析结果报告
with open("report.json", "r", encoding="utf-8") as f:
    report = json.load(f)
# 从数据里算出我们要展示的核心数字
total_alerts = len(report.get("alerts", []))
# 统计有多少个 IP 风险分大于 0（即真正的威胁 IP）
threat_ips = [ip for ip, p in report.get("ip_profiles", {}).items() if p.get("total_risk_score", 0) > 0]
total_threat_ips = len(threat_ips)
# 在网页上横向切出 3 个等宽的格子
col1, col2, col3 = st.columns(3)
# 在每个格子里画一个高大上的指标卡片
with col1:
    st.metric(label="📊 捕获威胁 IP 数", value=f"{total_threat_ips} 个")
with col2:
    st.metric(label="⚠️ 触发攻击告警数", value=f"{total_alerts} 次")
with col3:
    st.metric(label="🛡️ 防御处置就绪", value="100 %")

# 画一条小分割线和一个二级小标题
st.divider()
st.subheader("🎯 恶意 IP 威胁画像与情报清单")
# 从嵌套的字典里，把每个攻击 IP 整理成整整齐齐的“表格行”
table_rows = []
for ip, profile in report.get("ip_profiles", {}).items():
    # 只把真正有攻击行为（风险分 > 0）的 IP 放进表格
    if profile.get("total_risk_score", 0) > 0:
        table_rows.append({
            "🚨 IP 地址": ip,
            "📍 归属地": profile.get("location", "未知"),
            "🏢 网络运营商/身份": profile.get("isp", "未知"),
            "⚠️ 攻击次数": profile.get("attack_count", 0),
            "🔥 风险分数": profile.get("total_risk_score", 0),
            "🔴 严重等级": profile.get("max_severity", "LOW"),
            "🛠️ 攻击类型": ", ".join(profile.get("attack_types", []))
        })
# 按风险分数从大到小排序（最危险的排在第一行）
table_rows.sort(key=lambda x: x["🔥 风险分数"], reverse=True)
# 一行代码把它画成高科技交互式表格（use_container_width 让它横向撑满屏幕）
st.dataframe(table_rows, use_container_width=True)

with open("ai_result.json", "r", encoding="utf-8") as f:
    ai_data = json.load(f)

bad_ip = ai_data["priority_ip"]
reason = ai_data["reason"]

st.error(f"🚨 核心威胁目标：{bad_ip}\n\n**研判理由：** {reason}")

st.write("### 📋 针对各 IP 的深度研判分析：")

for finding in ai_data["findings"]:
    with st.expander(f"🔍 查看 IP [{finding['ip']}] 的详细分析 (AI 置信度: {finding['confidence']})"):
        st.write(finding["assessment"])

st.divider()
st.write("### 🚨 推荐应急处置：一键封禁命令")

st.caption("1. Linux 防火墙封禁命令 (iptables): ")
st.code(f"iptables -I INPUT -s {bad_ip} -j DROP", language="bash")

st.caption("2. Nginx 黑名单拦截配置 (nginx.conf): ")
st.code(f"deny {bad_ip};", language="nginx")