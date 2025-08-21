import os
import json
import asyncio
from playwright.async_api import async_playwright, Page
from pprint import pprint
import asyncio
# --- 配置常量 ---

# Google 表单的查看 URL
GOOGLE_FORM_URL = 'https://docs.google.com/forms/d/e/1FAIpQLSfdBHqlk-ZPk-jS0JDV4TTFvNf2eOBk-ghgIGaKatYf_UcjBA/viewform'

# 写死的团队名称和Email
TEAM_NAME = "HASS Lab"
EMAIL_ADDRESS = "grassedge@qq.com"

# 报告文件所在的根目录
REPORTS_DIR = 'reports'

# Google 表单字段的 XPath
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

# --- 报告解析与用户交互---

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

async def get_user_input(prompt: str) -> str:
    """在不阻塞事件循环的情况下异步获取用户输入。"""
    loop = asyncio.get_running_loop()
    # run_in_executor 将阻塞函数 (input) 放到一个单独的线程中执行
    return await loop.run_in_executor(
        None,  # 使用默认的线程池
        input, # 要执行的阻塞函数
        prompt # 传递给 input 函数的参数
    )

async def prompt_user_for_selection(reports: list) -> dict | None:
    """向用户显示报告列表，并让他们选择一个。"""
    print("\n--- 请选择要填充的报告 ---")
    for i, report in enumerate(reports):
        finding = report.get("Location or code reference", "无标题")
        print(f"  [{i+1}] {finding[:70]}...")
    while True:
        try:
            choice = await get_user_input(f"请输入报告编号 (1-{len(reports)})，或输入 'q' 退出: ")
            if choice.lower() == 'q': return None
            choice_index = int(choice) - 1
            if 0 <= choice_index < len(reports): return reports[choice_index]
            else: print(f"[!] 无效的选择。")
        except ValueError: print("[!] 无效的输入。")

async def get_user_inputs() -> tuple[str | None, str | None]:
    """提示用户输入 Bug 编号和附件链接。"""
    print("\n--- 请输入所需信息 ---")
    bug_number = await get_user_input("请输入 Bug 编号 (例如, 'BUG-001')，或输入 'q' 退出: ")
    if bug_number.lower() == 'q': return None, None
    attachment_link = await get_user_input("请输入附件链接 (可选, 可留空)，或输入 'q' 退出: ")
    if attachment_link.lower() == 'q': return None, None
    return bug_number, attachment_link

# --- Playwright 核心功能 ---

async def fill_form_with_playwright(page: Page, report_data: dict, bug_number: str, attachment_link: str):
    """使用 Playwright 和 XPath 填充表单。"""
    print("\n[*] 正在使用 Playwright 填充表单...")
    
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
            locator = page.locator(f"xpath={xpath}")
            
            if label in data_to_fill:
                value = data_to_fill[label]
                if value:
                    print(f"  - 正在填充: {label}")
                    await locator.fill(value)
            elif label == "Send me a copy":
                print(f"  - 正在勾选: {label}")
                await locator.click()

        print("\n[+] 所有字段已填充完毕！")
        print("[*] 当前标签页将保持打开状态，请您手动检查并提交表单。")
        print("[*] 提交当前表单后可继续选择下一个报告进行填充。")
        while page.url == GOOGLE_FORM_URL:
            await asyncio.sleep(1)
    except Exception as e:
        print(f"\n[!] 填充表单时发生错误: {e}")
        print("[*] 该标签页可能会关闭，请在下一个循环中重试。")
        await page.close()

async def main():
    """程序主入口 (基于 Playwright)"""
    reports = load_reports(REPORTS_DIR)
    if not reports:
        print("[!] 未找到任何报告，程序退出。")
        return

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        context = await browser.new_context()
        print("[*] 浏览器已启动。")
        
        while True:
            page = await context.new_page()
            print("\n[*] 页面加载与信息输入将同步进行...")

            # 定义一个协程来处理所有用户交互
            async def get_all_user_data():
                selected_report = await prompt_user_for_selection(reports)
                if not selected_report:
                    return None, None, None  # 用户取消

                bug_number, attachment_link = await get_user_inputs()
                if bug_number is None:
                    return None, None, None  # 用户取消
                
                return selected_report, bug_number, attachment_link

            # 并发运行页面加载和用户输入流程
            # page.goto 的返回值是 response，我们这里忽略它
            _, user_data = await asyncio.gather(
                page.goto(GOOGLE_FORM_URL),
                get_all_user_data()
            )
            
            selected_report, bug_number, attachment_link = user_data

            # 如果用户在任何一步取消，则退出循环
            if selected_report is None:
                print("[*] 用户取消操作，正在关闭标签页...")
                await page.close()
                break

            # 此时，页面已加载，数据也已输入完毕
            await fill_form_with_playwright(page, selected_report, bug_number, attachment_link)
        
        print("\n[*] 程序结束，正在关闭浏览器...")
        await browser.close()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] 检测到用户中断，程序退出。")