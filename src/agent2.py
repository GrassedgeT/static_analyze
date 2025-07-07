# %%
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_deepseek import ChatDeepSeek
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import SystemMessage
from langchain.agents import AgentExecutor, create_tool_calling_agent
from file_tools import read_sv_file, get_svfiles_path
import os

with open("../data/module_info/keymgr.json", "r") as f:
        module_info = f.read()
file_paths = get_svfiles_path("keymgr")
# print(file_paths)
prompt = f"""
You are HardwareSecurityExpert, an advanced AI assistant specialized in finding security vulnerabilities in hardware designs, particularly in SystemVerilog RTL code.
Your mission is to perform a detailed vulnerability analysis on a specific IP module from the OpenTitan project. 

CAPABILITIES AND ANALYSIS METHODS:
1. Static RTL Analysis:
   - Identify sensitive modules and signals (keys, control bits, security state machines)
   - Examine state machine implementations for bugs or exploitable states
   - Find potential timing issues, race conditions, or reset vulnerabilities
   - Detect improper isolation between security domains
   - Spot hardcoded secrets, debug modes, or test logic left in the design
2. Possible Attack Scenarios to Consider:
Memory and Address Management Flaws
Access Control & Privilege Escalation
Insecure Debug & Test Interfaces
Core Logic & Functional Bugs
State & Configuration Management Flaws
Cryptographic Weaknesses
Incorrect signal logic, such as mistakenly hardcoding signals that require dynamic updates as constant values
and other CWE Hardware-Specific Security Vulnerabilities.

Your entire output MUST be a single, valid JSON object without any additional text, explanations, or markdown formatting. The structure must be as follows:
```json
{{
  "identified_vulnerabilities": [
    {{
      "description": "A clear, concise explanation of the weakness. For example, 'The main state machine does not have a default case, which could lead to a lockup state if an undefined state is reached.'",
      "location": "source file name and line number, e.g., 'hmac_top_reg.sv:123-456'",
      "code_snippet": "
        The specific and relevant lines of Verilog/SystemVerilog code where the vulnerability exists.
      ",
      "impact": "The security consequence of the vulnerability.",
      "trigger_condition": "How an attacker or specific event could trigger this vulnerability.",
      "recommendations": "Actionable advice for the hardware designer to fix the issue."
    }},
    ...
  ]
}}

User input:
Pre processed information about the target IP module:
{ module_info }
File name: {"keymgr_reg_top"}
RTL code:
{read_sv_file(file_paths['keymgr_reg_top.sv'])}
"""
# print(prompt)

model = ChatOpenAI(
    model="claude-opus-4-20250514-thinking",
    api_key=os.getenv("OPEN_API_KEY", ""),
    base_url="https://chatbox.isrc.ac.cn/api", 
    max_completion_tokens=65536,
)

# model = ChatDeepSeek(
#     model="deepseek-reasoner",
#     temperature=0.5,
# )
result = model.invoke(prompt)
with open("../results/keymgr_claude.json", "w") as f:
    f.write(result.text())

# %%
