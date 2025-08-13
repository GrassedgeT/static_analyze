import os
import json
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from pprint import pprint

# --- 配置常量 ---

# Google 表单的查看 URL
GOOGLE_FORM_URL = 'https://docs.google.com/forms/d/e/1FAIpQLSfdBHqlk-ZPk-jS0JDV4TTFvNf2eOBk-ghgIGaKatYf_UcjBA/viewform'

# 写死的团队名称和Email
TEAM_NAME = "HASS Lab"
EMAIL_ADDRESS = "grassedge@qq.com"

# 报告文件所在的根目录
REPORTS_DIR = 'reports'

# Google 表单字段的 XPath (根据用户提示修正)
FORM_FIELD_XPATHS = {
    "Email": "/html/body/div[1]/div[2]/form/div[2]/div/div[2]/div[1]/div/div[1]/div[2]/div[1]/div/div[1]/input",
    "Team name": "/html/body/div[1]/div[2]/form/div[2]/div/div[2]/div[2]/div/div/div[2]/div/div[1]/div/div[1]/input",
    "Bug number": "/html/body/div[1]/div[2]/form/div[2]/div/div[2]/div[3]/div/div/div[2]/div/div[1]/div/div[1]/input",
    "Security feature bypassed": "/html/body/div[1]/div[2]/form/div[2]/div/div[2]/div[4]/div/div/div[2]/div/div[1]/div/div[1]/input",
    "Finding": "/html/body/div[1]/div[2]/form/div[2]/div/div[2]/div[5]/div/div/div[2]/div/div[1]/div[2]/textarea",
    "Location or code reference": "/html/body/div[1]/div[2]/form/div[2]/div/div[2]/div[6]/div/div/div[2]/div/div[1]/div[2]/textarea",
    "Detection method": "/html/body/div[1]/div[2]/form/div[2]/div/div[2]/div[7]/div/div/div[2]/div/div[1]/div[2]/textarea",
    "Security impact": "/html/body/div[1]/div[2]/form/div[2]/div/div[2]/div[8]/div/div/div[2]/div/div[1]/div[2]/textarea",
    "Adversary profile": "/html/body/div[1]/div[2]/form/div[2]/div/div[2]/div[9]/div/div/div[2]/div/div[1]/div[2]/textarea",
    "Proposed mitigation": "/html/body/div[1]/div[2]/form/div[2]/div/div[2]/div[10]/div/div/div[2]/div/div[1]/div[2]/textarea",
    "CVSSv3.1 score and severity": "/html/body/div[1]/div[2]/form/div[2]/div/div[2]/div[11]/div/div/div[2]/div/div[1]/div[2]/textarea",
    "CVSSv3.1 Details": "/html/body/div[1]/div[2]/form/div[2]/div/div[2]/div[12]/div/div/div[2]/div/div[1]/div[2]/textarea",
    "Attachment link": "/html/body/div[1]/div[2]/form/div[2]/div/div[2]/div[13]/div/div/div[2]/div/div[1]/div/div[1]/input",
    "Send me a copy": "//*[@id=\"i65\"]"
}

# --- 报告解析与用户交互 ---

def load_reports(directory: str) -> list:
    """递归扫描指定目录，加载所有 .json 格式的报告文件。"""
    all_reports = []
    print(f"[*] 正在扫描目录: {directory}")
    if not os.path.isdir(directory):
        print(f"[!] 错误: 目录 '{directory}' 不存在。")
        return []
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith('.json'):
                filepath = os.path.join(root, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            all_reports.extend(data)
                        else:
                            print(f"[!] 警告: 文件 '{filepath}' 的格式不是预期的列表。")
                except Exception as e:
                    print(f"[!] 读取文件时发生错误 {filepath}: {e}")
    print(f"[*] 成功加载 {len(all_reports)} 份报告。")
    return all_reports

def prompt_user_for_selection(reports: list) -> dict | None:
    """向用户显示报告列表，并让他们选择一个。"""
    print("\n--- 请选择要填充的报告 ---")
    for i, report in enumerate(reports):
        finding = report.get("Finding", "无标题")
        print(f"  [{i+1}] {finding[:70]}...")
    while True:
        try:
            choice = input(f"请输入报告编号 (1-{len(reports)})，或输入 'q' 退出: ")
            if choice.lower() == 'q': return None
            choice_index = int(choice) - 1
            if 0 <= choice_index < len(reports): return reports[choice_index]
            else: print(f"[!] 无效的选择。")
        except ValueError: print("[!] 无效的输入。")

def get_user_inputs() -> tuple[str | None, str | None]:
    """提示用户输入 Bug 编号和附件链接。"""
    print("\n--- 请输入所需信息 ---")
    bug_number = input("请输入 Bug 编号 (例如, 'BUG-001')，或输入 'q' 退出: ")
    if bug_number.lower() == 'q': return None, None
    attachment_link = input("请输入附件链接 (可选, 可留空)，或输入 'q' 退出: ")
    if attachment_link.lower() == 'q': return None, None
    return bug_number, attachment_link

# --- Selenium 核心功能 ---

def fill_form_with_selenium(web,report_data: dict, bug_number: str, attachment_link: str):
    """并根据 XPath 填充表单。"""
    print("\n[*] 正在启动浏览器并导航到 Google 表单...")
    
    web.get(GOOGLE_FORM_URL)

    try:
        data_to_fill = {
            "Email": EMAIL_ADDRESS,
            "Team name": TEAM_NAME,
            "Bug number": bug_number,
            "Security feature bypassed": report_data.get("Security feature bypassed", ""),
            "Finding": report_data.get("Finding", ""),
            "Location or code reference": report_data.get("Location or code reference", ""),
            "Detection method": report_data.get("Detection method", ""),
            "Security impact": report_data.get("Security impact", ""),
            "Adversary profile": report_data.get("Adversary profile", ""),
            "Proposed mitigation": report_data.get("Proposed mitigation", ""),
            "CVSSv3.1 score and severity": report_data.get("CVSSv3.1 Base score and severity", ""),
            "CVSSv3.1 Details": report_data.get("CVSSv3.1 details", ""),
            "Attachment link": attachment_link
        }

        for label, xpath in FORM_FIELD_XPATHS.items():
            if label in data_to_fill:
                value = data_to_fill[label]
                if value:
                    print(f"  - 正在填充: {label}")
                    element = WebDriverWait(web, 10).until(EC.presence_of_element_located((By.XPATH, xpath)))
                    element.send_keys(value)
            elif label == "Send me a copy":
                print(f"  - 正在勾选: {label}")
                element = WebDriverWait(web, 10).until(EC.presence_of_element_located((By.XPATH, xpath)))
                web.execute_script("arguments[0].click();", element)

        print("\n[+] 所有字段已填充完毕！")
        print("[*] 浏览器将保持打开状态，请您手动检查并提交表单。")
    except Exception as e:
        print(f"\n[!] 填充表单时发生错误: {e}")
    finally:
        if 'web' in locals() and 'e' in locals():
             web.quit()

# --- 主程序 ---

def main():
    """程序主入口"""
    web = webdriver.Chrome()
    reports = load_reports(REPORTS_DIR)
    if not reports:
        print("[!] 未找到任何报告，程序退出。")
        return

    while True:
        web.get(GOOGLE_FORM_URL)
        selected_report = prompt_user_for_selection(reports)
        if not selected_report:
            print("[*] 用户取消操作，程序退出。")
            return
        bug_number, attachment_link = get_user_inputs()
        if bug_number is None:
            print("[*] 用户取消操作，程序退出。")
            return

        fill_form_with_selenium(web,selected_report, bug_number, attachment_link)

if __name__ == '__main__':
    main()