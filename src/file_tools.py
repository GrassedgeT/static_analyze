# %%
# 此文件包含对opentitan项目源代码进行目录遍历和文件读取的相关工具
opentitian_src = "/home/cao/Projects/hack@ches_p1_25"


# %%
import os
import glob
import json

# 定义模块路径
hw_ip_path = os.path.join(opentitian_src, "hw", "ip")
hw_top_earlgrey = os.path.join(opentitian_src, "hw", "top_earlgrey")
hw_top_earlgrey_ip_path = os.path.join(opentitian_src, "hw", "top_earlgrey", "ip")
hw_top_earlgrey_ip_autogen_path = os.path.join(opentitian_src, "hw", "top_earlgrey", "ip_autogen")
hw_vendor_ibex_path = os.path.join(opentitian_src, "hw", "vendor", "lowrisc_ibex")
# 存放各个模块路径的字典
module_dict = {}

# 扫描指定路径下的模块，并返回包含模块名称和路径的字典
def scan_modules(base_path, prefix=""):
    modules = {}
    
    if not os.path.exists(base_path):
        print(f"Warning: Path {base_path} does not exist")
        return modules
    
    # 检查路径是否为目录
    try:
        subdirs = [d for d in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, d))]
        
        for subdir in subdirs:
            module_path = os.path.join(base_path, subdir)
            rtl_path = os.path.join(module_path, "rtl")
            
            # 检查 rtl 目录是否存在
            if os.path.exists(rtl_path) and os.path.isdir(rtl_path):
                #如果rtl目录下有autogen子目录，则使用该子目录
                autogen_path = os.path.join(rtl_path, "autogen")
                if os.path.exists(autogen_path) and os.path.isdir(autogen_path):
                    rtl_path = autogen_path
                # 构建模块名称
                if prefix:
                    module_name = f"{prefix}_{subdir}"
                else:
                    module_name = subdir
                modules[module_name] = rtl_path
    except Exception as e:
        print(f"Error scanning {base_path}: {str(e)}")
    
    return modules
# 检测 model_list.json 文件是否存在
module_list_file = "../data/model_list.json"
if os.path.exists(module_list_file):
    with open(module_list_file, "r") as f:
        module_dict = json.load(f)  
else:
    # 扫描 hw/ip 目录下的模块
    hw_ip_modules = scan_modules(hw_ip_path)
    module_dict.update(hw_ip_modules)

    # 扫描 hw/top_earlgrey 目录下的模块
    top_earlgrey_ip_modules = scan_modules(hw_top_earlgrey_ip_path, prefix="top_earlgrey")
    module_dict.update(top_earlgrey_ip_modules)

    # 扫描 hw/top_earlgrey/ip_autogen 目录下的模块
    top_earlgrey_ip_autogen_modules = scan_modules(hw_top_earlgrey_ip_autogen_path, prefix="top_earlgrey")
    module_dict.update(top_earlgrey_ip_autogen_modules)

    # 特殊处理 hw/vendor/lowrisc_ibex
    ibex_rtl_path = os.path.join(hw_vendor_ibex_path, "rtl")
    if os.path.exists(ibex_rtl_path) and os.path.isdir(ibex_rtl_path):
        module_dict["lowrisc_ibex"] = ibex_rtl_path

    # 特殊处理 top_earlgrey 模块
    module_dict["top_earlgrey"] = os.path.join(hw_top_earlgrey, "rtl")

    print(f"Found {len(module_dict)} modules with rtl directories")
    # 将模块列表保存到 model_list.json 文件
    with open(module_list_file, 'w') as f:
        json.dump(module_dict, f, indent=2)
    print(f"Module list saved to {module_list_file}")


# %%
from langchain import tools
@tools.tool("get_svfiles_path")
def get_svfiles_path(module_name: str) -> dict[str, str]:
    """
    Get the sv files' path of the specified module.
    ATTENTION: `module_name` refers to the name of the overall functional module at a macro level, equivalent to the name of an IP, rather than a `module` in SystemVerilog.
    Args:
        module_name (str): The name of the module to get file paths for.
        
    Returns:
        dict: A dictionary with the file name as the key and file paths as the value.
    """
    if module_name not in module_dict:
        raise ValueError(f"Module {module_name} not found in the module list.")
    
    rtl_path = module_dict[module_name]
    # 读取 rtl 目录下的所有 .sv 文件,并忽略'.'开头的隐藏文件
    sv_files = os.listdir(rtl_path)
    sv_files = [f for f in sv_files if f.endswith('.sv') and not f.startswith('.')]
    sv_files = {f: os.path.join(rtl_path, f) for f in sv_files}
    if not sv_files:
        raise ValueError(f"No .sv files found in the module {module_name} at {rtl_path}.")
    return sv_files
# get_svfiles_path("top_earlgrey_pinmux")

# %%
@tools.tool("get_module_list")
def get_module_src(module_name: str) -> str:
    """
    Get the source path of the specified module.
    `module_name` refers to the name of the overall functional module at a macro level, equivalent to the name of an IP, rather than a `module` in SystemVerilog.
    Args:
        module_name (str): The name of the module to get the source path for.
        
    Returns:
        str: The source path of the module.
    """
    if module_name not in module_dict:
        raise ValueError(f"Module {module_name} not found in the module list.")
    
    return module_dict[module_name]
get_module_src("hmac")

# %%
def add_line_numbers(content: str) -> str:
    """
    Add line numbers to the content of a SystemVerilog file.
    
    Args:
        content (str): The content of the SystemVerilog file.
        
    Returns:
        str: The content with line numbers added.
    """
    lines = content.split('\n')
    marked_lines = []
    for i, line in enumerate(lines, 1):
        # 跳过空行，但保留行号
        if line.strip():
            marked_lines.append(f"/*Line{i}*/: {line}")
        else:
            marked_lines.append(f"/*Line{i}*/:")
    return '\n'.join(marked_lines)

@tools.tool("read_sv_file")
def read_sv_file(file_path: str) -> str:
    """
    Read the content of a SystemVerilog file with line number.
    
    Args:
        file_path (str): The path to the SystemVerilog file.
        
    Returns:
        str: The content of the SystemVerilog file.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File {file_path} does not exist.")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    return add_line_numbers(content)

# print(read_sv_file("/home/cao/Projects/hack@ches_p1_25/hw/ip/hmac/rtl/hmac.sv"))

# %%
def get_all_svfiles() -> list[str]:
    """
    Get a list of all SystemVerilog files in the module list.
    `module_name` refers to the name of the overall functional module at a macro level, equivalent to the name of an IP, rather than a `module` in SystemVerilog.
    Returns:
        list: A list of paths to all .sv files in the modules.
    """
    all_sv_files = []
    for module_name, rtl_path in module_dict.items():
        sv_files = [f for f in os.listdir(rtl_path) if f.endswith('.sv') and not f.startswith('.')]
        all_sv_files.extend([os.path.join(rtl_path, f) for f in sv_files])
    
    return all_sv_files

