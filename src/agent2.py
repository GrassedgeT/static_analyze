# %%
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_deepseek import ChatDeepSeek
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import SystemMessage
from langchain.agents import AgentExecutor, create_tool_calling_agent
from file_tools import read_sv_file, get_svfiles_path
import os

def construct_prompt(module_info, file_name, file_paths):
    return f"""
You are HardwareSecurityExpert, an advanced AI assistant specialized in finding security vulnerabilities in hardware designs, particularly in SystemVerilog RTL code.
Your mission is to perform a detailed vulnerability analysis on a specific IP module from the OpenTitan project. 

Possible Attack Scenarios to Consider:
Memory and Address Management Flaws
Access Control & Privilege Escalation
Insecure Debug & Test Interfaces
Core Logic & Functional Bugs
State & Configuration Management Flaws
Cryptographic Weaknesses
Incorrect signal logic, such as mistakenly hardcoding signals that require dynamic updates as constant values
and other CWE Hardware-Specific Security Vulnerabilities.

Your entire output MUST be a single, valid JSON object, start with '{{' end with '}}' Output plain text only, do not add md formatting modifiers. The structure must be as follows:
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
  ]
}}

User input:
Pre processed information about the target IP module:
{ module_info }
File name: {file_name}
RTL code:
{read_sv_file(file_paths[file_name])}
"""

     
def llm_invoke(model_name, module_name, file_name, prompt):
    model = ChatOpenAI(
        model=model_name,
        api_key=os.getenv("OPEN_API_KEY", ""),
        base_url="https://chatbox.isrc.ac.cn/api", 
        temperature=0.1,
    )

    # model = ChatDeepSeek(
    #     model="deepseek-reasoner",
    #     temperature=0.5,
    # )
    result = model.invoke(prompt)
    if not os.path.exists(f"../results/{model_name}/{module_name}"):
        os.makedirs(f"../results/{model_name}/{module_name}")
    with open(f"../results/{model_name}/{module_name}/{file_name}.json", "w") as f:
        f.write(result.text())
     
def analyze_module(model_name, module_name, file_name=None):
    with open(f"../data/module_info/{module_name}.json", "r") as f:
            module_info = f.read()
    file_paths = get_svfiles_path(module_name)
    
    # 对单个文件进行分析
    if file_name:
        print(f"{model_name}: Analyzing file {file_name}")
        prompt = construct_prompt(module_info, file_name, file_paths)
        llm_invoke(model_name, module_name, file_name, prompt)
    else:
        # 对模块下的的所有文件进行分析
        for file_name, file_path in file_paths.items():
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File {file_name} not found at {file_path}")
            # print(file_paths)
            prompt = construct_prompt(module_info, file_name, file_paths)
            print(f"{model_name}: Analyzing file {file_name}")  
            llm_invoke(model_name, module_name, file_name, prompt)
    print(f"{model_name}: Analysis {module_name} Completed")
        

# %%
# analyze_module("gemini-2.5-pro", "lowrisc_ibex", "ibex_cs_registers.sv")
# analyze_module("gemini-2.5-pro", "lowrisc_ibex", "ibex_pmp.sv")
# analyze_module("gemini-2.5-pro", "lowrisc_ibex", "ibex_id_stage.sv")
analyze_module("gemini-2.5-pro", "aes", "aes_cipher_core.sv")
# %%
