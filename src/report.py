# %%
import json
from typing import List, Dict, Any

import os
import sys
import asyncio
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import JsonOutputParser
from file_tools import get_svfiles_path, read_sv_file
# 为单个漏洞条目定义类型别名，以获得更好的类型提示
Vulnerability = Dict[str, Any]
# %%
def parse_vulnerabilities_from_file(file_path: str) -> List[Vulnerability]:
    """
    将包含漏洞描述列表的JSON文件解析为Python字典列表。

    Args:
        file_path: JSON文件的路径。

    Returns:
        一个字典列表，其中每个字典代表一个漏洞。
        如果文件未找到或包含无效的JSON，则会引发异常。
    
    Raises:
        json.JSONDecodeError: 如果文件内容不是有效的JSON。
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data
            
    except json.JSONDecodeError as e:
        print(f"错误: 从文件 '{file_path}' 解码JSON失败。详细信息: {e}")
        raise
# %%
def construct_report_prompt(vulnerability: Vulnerability, rtl_code: str) -> str:
    """
    为单个漏洞构建生成报告的prompt。

    Args:
        vulnerability: 单个漏洞信息的字典。
        rtl_code: 相关的RTL源代码。

    Returns:
        一个用于LLM的prompt字符串。
    """
    return f"""
You are a security vulnerability analysis and assessment experts, as well as experienced hardware engineers. Based on the vulnerability information and the RTL code provided, generate a detailed security analysis report.

Vulnerability Information:
{json.dumps(vulnerability, indent=2)}

RTL Code:
{rtl_code}

Based on the information above, analyze and caculate then generate a report with the following fields:
- "Security feature bypassed": Describe the security feature that is compromised.
- "Finding": A detailed description of the vulnerability.
- "Location or code reference": The file and line number of the vulnerability.
- "Detection method": Automate tools
- "Security impact": The potential consequences of the vulnerability.
- "Adversary profile": The type of attacker who could exploit this. 
- "Proposed mitigation": Actionable steps to fix the vulnerability.
- "CVSSv3.1 Base score and severity": The calculated CVSS score and severity (e.g., Medium (6.8)).
- "CVSSv3.1 details": The full CVSS vector string and detail.

Adversay profile must choose from:
Adversary Model
1 Unprivileged software at user-level mode
Executes on the core with user-level privileges but may exploit
bugs to mount privilege escalation attacks or bypass security
countermeasures
2 Physical attacker
Has physical possession of the device
3 Privileged software in supervisor mode
Executes on the core with Supervisor mode privilege but may
target other higher privilege levels or bypass security
countermeasures
4 Authorized debug access
Has the ability to unlock and debug a production device

Calculate the CVSS score based on the vulnerability's characteristics.

Output plain text only,do not add md formatting modifiers. 
Your entire output MUST be a single, valid JSON Object. Note: Escape characters (e.g., \, {{, }},\\n...) must be handled correctly.
Your Output Format:
{{
  "Security feature bypassed": "FSM Fault Detection / Alert System Integrity",
  "Finding": "The Finite State Machine's (FSM) default case, which is intended to catch illegal or undefined states, fails to assert the dedicated error signal 'fsm_err_o'. The line of code responsible for asserting this signal is commented out, preventing the module from notifying the system of a critical fault condition.",
  "Location or code reference": "keymgr_data_en_state.sv:128",
  "Detection method": "Manual inspection",
  "Security impact": "If a fault injection attack (e.g., voltage glitching, laser fault injection) or a single-event upset forces the FSM into an illegal state, the event will go completely undetected by the system's alert handler. This violates the 'fail-secure' principle, as the system is unaware that its integrity has been compromised. An attacker could repeatedly attempt fault attacks without triggering any countermeasures, significantly increasing the chances of a successful exploit.",
  "Adversary profile": "Physical attacker",
  "Proposed mitigation": "Uncomment the line fsm_err_o = 1'b1; within the default case. This will ensure that any entry into an illegal FSM state is immediately reported, allowing the system to take appropriate defensive actions, such as triggering an alert, wiping secrets, or resetting the device.",
  "CVSSv3.1 Base score and severity": "Medium (6.8)",
  "CVSSv3.1 details": "
CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H
Attack Vector: Physical. The attack requires providing an external clock source to the chip.
Attack Complexity: Low. Assuming physical access, the vulnerability is triggered by setting a register and providing a clock signal.
Privileges Required: Low. The attacker needs both physical access and low-level software privileges to write to the control register.
User Interaction: None.
Scope: Changed. By controlling the clock, an attacker can bypass security features and impact components beyond the immediate clock controller, compromising the entire chip's security authority.
Confidentiality, Integrity, Availability: High. The attack enables key extraction (Confidentiality), bypassing security checks (Integrity), and causing system-wide instability (Availability)
  "
}}
"""
# %%
async def async_llm_invoke_report(model_name: str, prompt: str) -> Dict[str, Any]:
    """
    异步调用LLM并解析返回的JSON报告。
    """
    output_parser = JsonOutputParser()
    model = ChatOpenAI(
        model=model_name,
        api_key=os.getenv("OPEN_API_KEY", ""),
        base_url="https://chatbox.isrc.ac.cn/api",
        temperature=0.1,
    )
    try:
        result = await model.ainvoke(prompt)
        # print(result.content)
        json_response = output_parser.parse(result.content)
        return json_response
    except Exception as e:
        print(f"Error decoding JSON from LLM response: {e}")
        # 在异步上下文中，最好返回None或特定错误对象，而不是重新引发
        return None

async def process_vulnerability_async(vuln: Vulnerability, rtl_code: str, model_name: str, index: int, total: int) -> Dict[str, Any]:
    """
    异步处理单个漏洞，生成报告。
    """
    print(f"Processing vulnerability {index}/{total}...")
    prompt = construct_report_prompt(vuln, rtl_code)
    try:
        report = await async_llm_invoke_report(model_name, prompt)
        if report:
            print(f"Successfully generated report for vulnerability {index}.")
            return report
        else:
            print(f"Failed to generate report for vulnerability {index} due to LLM error.")
            return None
    except Exception as e:
        print(f"Failed to generate report for vulnerability {index}: {e}")
        return None

async def main():
    model_name = 'gemini-2.5-pro'
    load_dotenv()
    if len(sys.argv) != 2:
        print("Usage: python report.py <path_to_vulnerability.json>")
        sys.exit(1)

    vulnerability_file_path = sys.argv[1]

    if not os.path.exists(vulnerability_file_path):
        print(f"Error: File not found at {vulnerability_file_path}")
        sys.exit(1)

    base_name = os.path.basename(vulnerability_file_path)
    file_name_without_ext = base_name.replace('.sv.json', '')
    module_dir = os.path.dirname(vulnerability_file_path)
    module_name = os.path.basename(module_dir)

    try:
        rtl_paths = get_svfiles_path(module_name)
        target_rtl_file = f"{file_name_without_ext}.sv"
        if target_rtl_file not in rtl_paths:
            alt_target_rtl_file = f"{module_name}.sv"
            if alt_target_rtl_file in rtl_paths:
                target_rtl_file = alt_target_rtl_file
            else:
                print(f"Error: RTL file for {file_name_without_ext} not found in module {module_name}.")
                sys.exit(1)
        
        rtl_file_path = rtl_paths[target_rtl_file]
        rtl_code = read_sv_file(rtl_file_path)
        vulnerabilities = parse_vulnerabilities_from_file(vulnerability_file_path)
        
        print(f"Generating reports for {len(vulnerabilities)} vulnerabilities from {base_name}...")

        coroutines = [
            process_vulnerability_async(vuln, rtl_code, model_name, i + 1, len(vulnerabilities))
            for i, vuln in enumerate(vulnerabilities)
        ]

        final_reports = []
        # 每次并发处理5个
        for i in range(0, len(coroutines), 5):
            batch = coroutines[i:i+5]
            results = await asyncio.gather(*batch)
            # 过滤掉失败的（None）结果
            final_reports.extend([r for r in results if r is not None])
            processed_count = min(i + 5, len(coroutines))
            remaining_count = len(coroutines) - processed_count
            print(f"Batch processed {processed_count}/{len(coroutines)} vulnerabilities. Remaining: {remaining_count}")

        if final_reports:
            report_dir = f"../reports/{model_name}/{module_name}"
            if not os.path.exists(report_dir):
                os.makedirs(report_dir)
            
            report_file_path = os.path.join(report_dir, f"{file_name_without_ext}_report.json")
            with open(report_file_path, 'w', encoding='utf-8') as f:
                json.dump(final_reports, f, indent=2)
            
            print(f"All {len(final_reports)} reports have been generated and saved to {report_file_path}")

    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())

# %%
