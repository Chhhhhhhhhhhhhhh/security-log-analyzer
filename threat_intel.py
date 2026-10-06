import requests
import ipaddress

def lookup_ip_info(ip):
    """
    输入一个 IP 地址，返回它的地理位置和网络运营商
    """
    try:
        # 1. 转换为 IP 对象
        ip_obj = ipaddress.ip_address(ip)
        # 2. 如果是内网 IP，直接返回内网标记
        if ip_obj.is_private or ip_obj.is_loopback:
            return {
                "location": "局域网/内网",
                "isp": "私有网络 (疑似靶场或内网渗透)"
            }
        # 3. 如果是公网 IP，发网络请求查询（设置 5 秒超时，防止卡死）
        url = f"http://ip-api.com/json/{ip}?lang=zh-CN"
        response = requests.get(url, timeout=5)
        data = response.json()
        # 4. 提取信息并打包返回
        country = data.get("country", "未知国家")
        city = data.get("city", "未知城市")
        isp = data.get("isp", "未知运营商")
        return {
            "location": f"{country} - {city}",
            "isp": isp
        }
    except Exception:
        # 如果断网或出错，安全降级，返回未知
        return {
            "location": "未知位置",
            "isp": "未知运营商"
        }
# ===== 测试一下这个函数 =====
if __name__ == "__main__":
    print("测试内网 IP:", lookup_ip_info("192.168.153.133"))
    print("测试公网 IP:", lookup_ip_info("8.8.8.8"))
