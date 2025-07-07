# This agent is designed to work with the RAG system and ast tools ,  
# which retrieves relevant documents based on queries.
# It will collect and analyze the AST of SystemVerilog files,
# and summarize the results that will pass to the next agent.
# %%
from rag import doc_retriver, cwe_retriver_tool
from ast_tools import analyze_sv_ast
from langchain import tools
from dependency_tools import analyze_module_dependencies
mytools = [
    doc_retriver,
    cwe_retriver_tool,
]
# %%
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_deepseek import ChatDeepSeek
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import SystemMessage
from langchain.agents import AgentExecutor, create_tool_calling_agent

import os
# GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
# print(f"使用的API密钥: {GEMINI_API_KEY}") 

system_prompt = f"""
你是一个专注于硬件安全领域的高级研究助理。你的任务是为一个特定的 OpenTitan Soc的 IP 模块进行深入的前置信息调研和分析，为后续 Agent2 的漏洞分析工作提供全面、结构化的数据支持。

你可以使用以下工具来完成任务：
{mytools}
你的任务流程如下：
1. 识别目标模块：从用户提供的名称开始。
2. 深度文档调研：
你将接入一个包含 OpenTitan 官方文档的 RAG 数据库。
使用 `doc_retriver` 工具，进行多次、有针对性的查询，以全面覆盖模块的各个方面。
你需要调研的核心文档包括但不限于：`README.md`, `doc/theory_of_operation.md`, `doc/programmers_guide.md`, `registers.md` (寄存器定义), 以及任何关于接口 (interfaces.md) 的描述。
你的目标是提取并整合所有对漏洞分析有潜在价值的信息。重点关注但不限于：模块的功能、状态机、外部接口、总线协议、寄存器（特别是那些控制关键操作或安全特性的寄存器）、中断、时钟/复位逻辑、数据流路径、安全对策（如硬件加扰、内存完整性保护）等。
3. 分析用户提供的补充信息：
分析用户提供的模块代码的语法树 (`abstract_syntax_tree`)，识别关键的逻辑结构、数据处理路径和控制流。
分析用户提供的模块依赖关系 (`dependencies`)，了解该模块与其他 IP、库或总线的交互关系。
4. 识别潜在的 CWE：
基于以上所有信息（文档、语法树、依赖关系），识别出可能适用于此硬件模块的常见缺陷枚举 (CWE) 条目。
使用 `cwe_retriver` 工具，根据你识别的攻击面（如寄存器接口、总线交互）和功能（如 FSM、加密操作），查询相关的 CWE 编号和描述。例如，你可以查询 "CWE for improper hardware state machine management" 或 "CWE related to insecure register access control"。
5. 生成最终的 JSON 输出：将所有分析结果整合到一个结构化的 JSON 对象中。
输出的所有信息必须要有明确的来源和依据，确保每个结论都可以追溯到具体的文档或代码分析结果，不能凭空捏造。
必须遵循的 JSON 输出结构：
{{
  "ip_module_name": "[IP模块的名称]",
  "documentation_analysis": {{
    "executive_summary": "对该模块功能、目的和核心操作的高度概括性总结，旨在让分析人员快速了解其作用。",
    "theory_of_operation": {{
      "core_functionality": "详细描述模块的核心功能和设计理念。它解决了什么问题？它的主要工作流程是什么？",
      "state_machines": [
        {{
          "fsm_name": "状态机的名称或描述",
          "description": "该状态机的功能、状态转换条件、以及每个状态下的关键操作。这是漏洞分析的重点。",
          "states": ["STATE_IDLE", "STATE_CMD_EXEC", "STATE_ERROR"]
        }}
        ... (更多状态机)
      ],
      "data_flow": "描述数据如何在模块内部以及进出模块时被处理、转换和流动的路径。重点关注未经检查的数据或敏感数据路径。"
    }},
    "interfaces_and_attack_surfaces": {{
      "bus_interfaces": [
        {{
          "interface_type": "例如 'TileLink Uncached Lite (TL-UL)'",
          "description": "该总线接口的用途、连接的设备、以及它所承载的命令和数据类型。",
          "potential_vulnerabilities": "与此接口相关的潜在漏洞，如协议违规、访问控制缺失、侧信道等。"
        }}
        ... (更多总线接口)
      ],
      "direct_io": [
        {{
          "pin_name": "物理引脚或信号的名称",
          "direction": "Input/Output/InOut",
          "description": "该信号的用途，以及它如何影响模块的行为。"
        }}
        ... (更多直接IO信号)
      ],
      "clocks_and_resets": "描述模块的时钟域、复位信号（类型和作用），以及跨时钟域交互（CDC）的潜在风险点。"
    }},
    "programming_model": {{
      "register_map_analysis": [
        {{
          "register_name": "寄存器的名称",
          "offset": "寄存器的地址偏移",
          "width": "寄存器的位宽",
          "access_type": "RW/RO/WO/W1C",
          "description": "寄存器的功能描述，每个字段的详细作用。",
          "security_implication": "对该寄存器的不当访问或配置可能导致的安全问题。例如：'该寄存器控制安全状态，意外清零将禁用所有保护' 或 '该寄存器为数据缓冲区，可能存在溢出风险'。"
        }}
        ... (更多寄存器)
      ],
      "interrupts": [
        {{
          "interrupt_name": "中断的名称",
          "description": "触发此中断的条件，以及软件应如何响应。不正确的中断处理可能导致系统不稳定或被利用。"
        }}
        ... (更多中断)
      ]
    }},
    "security_features": [
      {{
        "feature_name": "安全特性的名称，如 '寄存器访问控制'",
        "description": "该安全特性的工作原理和保护目标。",
        "potential_weaknesses": "该特性可能存在的设计缺陷或实现漏洞，例如 '访问控制列表固定，无法更新' 或 '仅在特定模式下生效'。"
      }}
      ... (更多安全特性)
    ]
  }},
  "abstract_syntax_tree_summary": "基于提供的语法树，对代码结构、关键算法、复杂循环或条件语句的分析总结。指出可能存在逻辑错误的区域。",
  "dependency_summary": "基于提供的依赖关系，分析模块与外部世界的交互边界。指出哪些依赖项是可信的，哪些是潜在的攻击向量来源。"
  "potential_cwe_identification": [
    {{
      "cwe_id": "例如 'CWE-1271'",
      "cwe_name": "例如 'Unrestricted externally-controlled modification of Finite State Machine (FSM)'",
      "description": "从检索工具中获得的官方CWE描述。",
      "rationale_for_inclusion": "详细说明为什么认为此CWE与目标模块相关。必须将理由与前述分析的具体发现联系起来，例如：'模块的FSM状态转换由可被软件直接写入的寄存器（REG_CTRL）控制，且没有额外的保护机制，符合CWE-1271的描述。'"
    }},
    {{
      "cwe_id": "例如 'CWE-1242'",
      "cwe_name": "例如 'Use of Predictable Algorithm in Random Number Generator'",
      "description": "官方CWE描述。",
      "rationale_for_inclusion": "将此CWE与分析发现联系起来的具体理由。"
    }}
  ]
}}
你的所有输出必须是一个单一、完整的、格式正确的 JSON 对象。不允许包含任何解释性文字、注释、Markdown 标记或任何在 JSON 对象之外的字符。
"""
hw_security_prompt = ChatPromptTemplate.from_messages(
    [
        SystemMessage(content=system_prompt),
        MessagesPlaceholder(variable_name="chat_history"),
        ("user", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad")
    ]
)

# model = ChatOpenAI(
#     model="gemini-2.5-pro",
#     api_key=os.getenv("OPEN_API_KEY", ""),
#     base_url="https://chatbox.isrc.ac.cn/api", 
#     max_completion_tokens=65536,
# )
model = ChatDeepSeek(
    model="deepseek-reasoner",
    temperature=0.5,
)


# model = ChatGoogleGenerativeAI(
#     model="gemini-2.5-pro",
# )
agent = create_tool_calling_agent(model, mytools, hw_security_prompt)

agent_executor = AgentExecutor(
    agent=agent,
    tools=mytools,
    verbose=True,
    return_intermediate_steps=True
)
async def pre_process_module_info(module_name: str):
    print(f"正在预处理： {module_name}模块信息")
    try:
        result = await agent_executor.ainvoke(
            {
                "input": f"""
                    Target IP Module: {module_name}

                    Abstract Syntax Tree Information:
                    {analyze_sv_ast(module_name)}

                    Dependency Information:
                    {analyze_module_dependencies(module_name)}
                """,
                "chat_history": []}) 
    except Exception as e:
        with open(f"../data/module_info/{module_name}_error.log", "w") as f:
            f.write(f"预处理 {module_name} 模块信息时发生错误：{str(e)}\n")
        return
    result = result['output']
    # 写入到文件
    with open(f"../data/module_info/{module_name}.json", "w") as f:
        f.write(result)
    print(f"预处理完成： {module_name}模块信息已保存到 ../data/module_info/{module_name}.json")
# pre_process_module_info("hmac")

# %%
import asyncio
from file_tools import module_dict
async def main():
    coroutines = [
        pre_process_module_info(module_name)
        for module_name in module_dict.keys()
    ]
    # 每次并发处理5个模块
    for i in range(0, len(coroutines), 5):
        await asyncio.gather(*coroutines[i:i+5])
        print(f"已处理 {i+5} 个模块，剩余 {len(coroutines) - (i + 5)} 个模块待处理。")

await main()
# %%
