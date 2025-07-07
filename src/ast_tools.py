# %%
from verible_syntax_tool import verible_verilog_syntax
import pickle, os, anytree
from file_tools import get_svfiles_path, get_all_svfiles
from langchain import tools
import textwrap

def parse_sv_files(rtl_files):
    """
    Parse the SystemVerilog files and return their ASTs.
    
    Args:
        rtl_files (list): A list of paths to SystemVerilog files.
        
    Returns:
        dict: A dictionary where keys are file paths and values are their ASTs.
    """
    parser = verible_verilog_syntax.VeribleVerilogSyntax(executable = '/usr/bin/verible-verilog-syntax')
    return parser.parse_files(rtl_files)

def _get_node_text(node, tag):
    """Safely get text from a child node by its tag."""
    child = node.find(lambda n: hasattr(n, 'tag') and n.tag == tag)
    return child.text if child else "Unnamed"

def _extract_ports(module_node):
    """Extracts port information from a module declaration node."""
    ports = []
    port_list = module_node.find(lambda n: hasattr(n, 'tag') and n.tag == 'kPortDeclarationList')
    if not port_list:
        return ports
    
    for port in port_list.find_all(lambda n: hasattr(n, 'tag') and n.tag == 'kPort'):
        port_name_node = port.find(lambda n: hasattr(n, 'tag') and n.tag == 'SymbolIdentifier')
        if port_name_node:
            port_info = {'name': port_name_node.text}
            # Further analysis can be added here, e.g., direction, type
            ports.append(port_info)
    return ports

def _extract_parameters(module_node):
    """Extracts parameter information from a module declaration node."""
    params = []
    param_nodes = module_node.find_all(lambda n: hasattr(n, 'tag') and 'Parameter' in n.tag)
    for param in param_nodes:
        param_name_node = param.find(lambda n: hasattr(n, 'tag') and n.tag == 'SymbolIdentifier')
        param_value_node = param.find(lambda n: hasattr(n, 'tag') and ('Expression' in n.tag or 'kConstant' in n.tag))
        if param_name_node:
            params.append({
                'name': param_name_node.text,
                'value': param_value_node.text if param_value_node else 'N/A'
            })
    return params

def _extract_instances(module_node):
    """Extracts submodule instance information."""
    instances = []
    instance_nodes = module_node.find_all(lambda n: hasattr(n, 'tag') and n.tag == 'kGateInstance')
    for instance in instance_nodes:
        type_name = "Unknown"
        module_type_node = instance.find(lambda n: hasattr(n, 'tag') and n.tag == 'kGateInstanceType')
        if module_type_node:
            type_id = module_type_node.find(lambda n: hasattr(n, 'tag') and n.tag == 'SymbolIdentifier')
            if type_id:
                type_name = type_id.text

        instance_name = _get_node_text(instance, 'SymbolIdentifier')
        
        connections = []
        port_list = instance.find(lambda n: hasattr(n, 'tag') and (n.tag == 'kActualParameterList' or n.tag == 'kPortActualList'))
        if port_list:
            conn_nodes = port_list.find_all(lambda n: hasattr(n, 'tag') and n.tag == 'kActualNamedPort')
            for conn in conn_nodes:
                port_name = _get_node_text(conn, 'SymbolIdentifier')
                expr = conn.find(lambda n: hasattr(n, 'tag') and 'Expression' in n.tag)
                connections.append({
                    'port': port_name,
                    'signal': expr.text if expr else '?'
                })

        instances.append({
            'instance_name': instance_name,
            'type': type_name,
            'connections': connections
        })
    return instances

def _extract_behavioral_models(module_node):
    """Extracts behavioral models (e.g., always blocks)."""
    behaviors = []
    always_blocks = module_node.find_all(lambda n: hasattr(n, 'tag') and 'kAlways' in n.tag)
    for block in always_blocks:
        sensitivity_list = []
        sens_list_node = block.find(lambda n: hasattr(n, 'tag') and n.tag == 'kSensitivityList')
        if sens_list_node:
            signals = sens_list_node.find_all(lambda n: hasattr(n, 'text') and n.text)
            sensitivity_list = [s.text for s in signals]
        
        statements = block.find_all(lambda n: hasattr(n, 'tag') and 'Statement' in n.tag)
        
        behaviors.append({
            'type': block.tag,
            'sensitivity_list': sensitivity_list,
            'statement_count': len(statements)
        })
    return behaviors

def _extract_dataflow_models(module_node):
    """Extracts dataflow models (e.g., continuous assignments)."""
    dataflows = []
    assign_stmts = module_node.find_all(lambda n: hasattr(n, 'tag') and n.tag == 'kContinuousAssignmentStatement')
    for stmt in assign_stmts:
        lhs_node = stmt.find(lambda n: hasattr(n, 'tag') and 'kNetVariableAssignment' in n.tag)
        if lhs_node:
            lhs_name = _get_node_text(lhs_node, 'SymbolIdentifier')
            expr_node = lhs_node.find(lambda n: hasattr(n, 'tag') and 'Expression' in n.tag)
            rhs_text = expr_node.text if expr_node else "N/A"
            dataflows.append({
                'target': lhs_name,
                'expression': textwrap.shorten(rhs_text, width=80)
            })
    return dataflows

def extract_sv_info(tree):
    """
    Extracts detailed information from a SystemVerilog AST.
    """
    analysis_results = []
    module_nodes = anytree.findall(tree, lambda node: hasattr(node, 'tag') and node.tag == 'kModuleDeclaration')

    for module in module_nodes:
        module_name = _get_node_text(module, 'SymbolIdentifier')
        
        module_info = {
            'module_name': module_name,
            'parameters': _extract_parameters(module),
            'ports': _extract_ports(module),
            'instances': _extract_instances(module),
            'behavioral_models': _extract_behavioral_models(module),
            'dataflow_models': _extract_dataflow_models(module)
        }
        analysis_results.append(module_info)
        
    return analysis_results

# @tools.tool("analyze_sv_ast")
def analyze_sv_ast(module_name):
    """
    Analyze the SystemVerilog AST for a specific module to extract detailed information,
    including module hierarchy, behavior models, and dataflow models.
    `module_name` refers to the name of the overall functional module at a macro level, 
    equivalent to the name of an IP, rather than a `module` in SystemVerilog.
    
    Args:
        module_name (str): The name of the IP/module to analyze.
        
    Returns:
        dict: A dictionary where keys are sv file names and values are the extracted
              information for each SystemVerilog module within that file.
    """
    sv_files = get_svfiles_path(module_name)
    result = {}
    for file_name, file_path in sv_files.items():
        if file_path not in ast_trees:
            raise ValueError(f"AST for {file_path} not found. Please parse the file first.")
        
        cst = ast_trees[file_path]
        # The main analysis function is called here
        analysis_data = extract_sv_info(cst.tree)
        result[file_name] = analysis_data
    return result

def extract_modules_and_instances(cst):
    modules_info = []
    instances_info = []

    # 收集模块声明信息
    for module in cst.iter_find_all({"tag": "kModuleDeclaration"}):
        module_info = {
            "header_text": "",
            "name": "",
            "ports": [],
            "parameters": [],
        }

        # 找到模块头
        header = module.find({"tag": "kModuleHeader"})
        if not header:
            continue

        module_info["header_text"] = header.text

        # 找到模块名称
        name = header.find({"tag": ["SymbolIdentifier", "EscapedIdentifier"]})
        if name:
            module_info["name"] = name.text

        # 获取端口列表
        for port in header.iter_find_all({"tag": ["kPortDeclaration", "kPort"]}):
            port_id = port.find({"tag": ["SymbolIdentifier", "EscapedIdentifier"]})
            if port_id:
                module_info["ports"].append(port_id.text)

        # 获取参数列表
        for param in header.iter_find_all({"tag": ["kParamDeclaration"]}):
            param_id = param.find({"tag": ["SymbolIdentifier", "EscapedIdentifier"]})
            if param_id:
                module_info["parameters"].append(param_id.text)

        modules_info.append(module_info)

    # 收集实例化信息
    for instance in cst.iter_find_all({"tag": "kInstantiationBase"}):
        instance_info = {
            "module_name": "",
            "instance_name": "",
            "connections": {},
            "code": instance.text,
        }

        # 找到模块类型
        module_type = instance.find({"tag": "kDataType"})
        if module_type:
            module_name_node = module_type.find({"tag": "kUnqualifiedId"})
            if module_name_node:
                instance_info["module_name"] = module_name_node.find({"tag": "SymbolIdentifier"}).text
            else:
                continue

        # 找到实例名称
        instance_id = instance.find({"tag": "kGateInstance"})
        if instance_id:
            instance_info["instance_name"] = instance_id.find({"tag": "SymbolIdentifier"}).text
            # assert instance_info['instance_name'].startswith('u_'), f"instantiation{instance_info}"
        else:
            continue

        # 获取连接的端口
        for connection in instance.iter_find_all({"tag": "kActualNamedPort"}):
            port_id = connection.find({"tag": "SymbolIdentifier"})
            if port_id:
                try:
                    connection_id = connection.find({"tag": "kParenGroup"}).find({"tag": "kReference"})
                    if connection_id:
                        instance_info["connections"][port_id.text] = connection_id.find({"tag": "SymbolIdentifier"}).text
                except:
                    instance_info["connections"][port_id.text] = port_id.text
                    # for prefix, _, node in anytree.RenderTree(connection):
                    #     print(f"\033[90m{prefix}\033[0m{node.to_formatted_string()}")
                    # raise ""

        instances_info.append(instance_info)

    return modules_info, instances_info

def analyze_sv_ast_old(module_name):
    """
    Analyze the SystemVerilog AST for a specific module and extract module and instance information.
    `module_name` refers to the name of the overall functional module at a macro level, equivalent to the name of an IP, rather than a `module` in SystemVerilog.
    Args:
        module_name (str): The name of the module to analyze.
        
    Returns:
        dict: A dictionary containing module(this is the System verilog 'module') and instance information. 
              keys are sv file names, 
              values are tuples of (modules_info, instances_info).     
    """
    sv_files = get_svfiles_path(module_name)
    result = {}
    for file_name, file_path in sv_files.items():
        if file_path not in ast_trees:
            raise ValueError(f"AST for {file_path} not found. Please parse the file first.")
        
        cst = ast_trees[file_path]
        modules_info, instances_info = extract_modules_and_instances(cst.tree)
        result[file_name] = (modules_info, instances_info)
    return result
# %%
# Load ASTs from cache or parse them if not available
rtl_files = get_all_svfiles()

if 'ast_trees' not in locals():
    pickle_path = '../data/ast_trees.pkl'
    if os.path.exists(pickle_path):
        with open(pickle_path, 'rb') as f:
            ast_trees = pickle.load(f)
    else:
        ast_trees = parse_sv_files(rtl_files)
        os.makedirs(os.path.dirname(pickle_path), exist_ok=True)
        with open(pickle_path, 'wb') as f:
            pickle.dump(ast_trees, f)

print("ast_tools initialized, ready to use.")
