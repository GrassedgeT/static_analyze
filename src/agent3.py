# %%
import os

from langchain_deepseek import ChatDeepSeek
from file_tools import get_svfiles_path, read_sv_file
from langchain_openai import ChatOpenAI
import time
from langchain_core.output_parsers import JsonOutputParser, StrOutputParser
def get_results():
    """
    返回results目录下所有报告的路径
    返回一个字典，key为路径中.sv.json前，第一个‘/’后的模块名称，value为路径
    """
    import os
    base_dir = "../results"
    result_dict = {}
    
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith(".sv.json"):
                # 获取相对路径（相对于base_dir）
                rel_path = os.path.relpath(os.path.join(root, file), base_dir)
                # 替换路径分隔符为'/'
                rel_path = rel_path.replace(os.sep, '/')
                
                module_name = file.replace(".json", "")
                result_dict[module_name] = os.path.join(base_dir, rel_path)
    return result_dict
# %%
module_name = "hmac"
file_name = "hmac_reg_top.sv"
results_path = get_results()
hmac_files = get_svfiles_path(module_name)
rtl_code = read_sv_file(hmac_files[file_name])
with open(results_path[file_name], encoding="utf-8") as f:
     vulnerabilities = f.read()

# %%
def generate_assertion(module_name, rtl_code, result, model_name):
    """
    生成断言
    """
    model = ChatOpenAI(
        model=model_name,
        api_key=os.getenv("OPEN_API_KEY", ""),
        base_url="https://chatbox.isrc.ac.cn/api",
        temperature=0.1,
    )
    output_parser = JsonOutputParser()

    prompt = f"""
    You are a security vulnerability analysis and assessment experts, as well as experienced hardware engineers. Based on the vulnerability information and the RTL code provided, generate riscv rtl assertions code for each vulnerability to validate the vulnerability.
    RTL Code:
    {rtl_code}
    Potential Vulnerability Information:
    {result}
    Output plain text only,do not add md formatting modifiers. 
    Your entire output MUST be a single, valid JSON Object. Note: Escape characters (e.g., \\, {{, }},\\n...) must be handled correctly.
    The number of assertions should be the same as the number of vulnerabilities and the order should be the same.
    Output format:
    [
        {{
            "assertion":"rtl code",
            "description":"description"
        }},
        {{
            "assertion":"rtl code",
            "description":"description"
        }}
        ...
    ]
    """
    try:
        result = model.invoke(prompt)
        # print(result.content)
        json_response = output_parser.parse(result.content)
        return json_response
    except Exception as e:
        print(f"Error decoding JSON from LLM response: {e}")
        # 在异步上下文中，最好返回None或特定错误对象，而不是重新引发
        return None
# %%
def validate_assertion(assertions, rtl_code, vulnerabilities, model_name):
    """
    验证断言
    """
    # model = ChatOpenAI(
    #     model=model_name,
    #     api_key=os.getenv("OPEN_API_KEY", ""),
    #     base_url="https://chatbox.isrc.ac.cn/api",
    #     temperature=0.1,
    # )
    model = ChatDeepSeek(
        model="deepseek-reasoner",
        temperature=0,
    )
    output_parser = StrOutputParser()

    def construct_prompt(rtl_code, assertion, vulnerability):
        return f"""
            You are a security vulnerability analysis and assessment experts, as well as experienced hardware engineers. Based on the vulnerability information the assertion and the RTL code provided, Simulate and validate the assertion, give a score（1-10） to represent the possibility of this vulnerability existing.
            RTL Code:
            {rtl_code}
            Assertion:
            {assertion}
            Potential Vulnerability Information:
            {vulnerability}
            Output plain text only,do not add md formatting modifiers. 
            Your entire output MUST ONLY be a number from 1.0 to 10.0.
        """
    
    scores = []
    for assertion, vulnerability in zip(assertions, vulnerabilities):
        prompt = construct_prompt(rtl_code, assertion, vulnerability)
        try:
            result = model.invoke(prompt)
            # print(result.content)
            score = output_parser.parse(result.content)
            scores.append(score)
        except Exception as e:
            print(f"Error decoding JSON from LLM response: {e}")
    return scores

# %% 
def evaluate_vulnerabilities(rtl_code, vulnerabilities, model_name):
    """
    重新评估漏洞
    """
    model = ChatOpenAI(
        model=model_name,
        api_key=os.getenv("OPEN_API_KEY", ""),
        base_url="https://chatbox.isrc.ac.cn/api",
        temperature=0.1,
    )
    output_parser = StrOutputParser()

    def construct_prompt(rtl_code, vulnerability):
        return f"""
            You are a security vulnerability analysis and assessment experts, as well as experienced hardware engineers. Based on the vulnerability information  and the RTL code provided, evaluate the vulnerability, give a score（1-10） to represent the possibility of this vulnerability existing.
            RTL Code:
            {rtl_code}
            Assertion:
            {vulnerability}
            Output plain text only,do not add md formatting modifiers. 
            Your entire output MUST ONLY be a number from 1.0 to 10.0.
        """
    scores = []
    for assertion, vulnerability in zip(assertions, vulnerabilities):
        prompt = construct_prompt(rtl_code, vulnerability)
        try:
            result = model.invoke(prompt)
            # print(result.content)
            score = output_parser.parse(result.content)
            scores.append(score)
        except Exception as e:
            print(f"Error decoding JSON from LLM response: {e}")
    return scores

# %%
assertions = generate_assertion(module_name, rtl_code, vulnerabilities, "Tongyi-Zhiwen/QwenLong-L1-32B")
print(assertions)

#%% 
# validate_assertion(assertions, rtl_code, vulnerabilities, "deepseek-chat")
evaluate_vulnerabilities(rtl_code, vulnerabilities, "DeepSeek-V3")
# %%
