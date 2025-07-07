# %% 
from langchain_core import tools
from file_tools import get_svfiles_path, module_dict
from ast_tools import analyze_sv_ast_old
# @tools.tool("analyze_module_dependencies")
@tools.tool("analyze_module_dependencies")
def analyze_module_dependencies(module_name):
    """
    Analyze dependencies between modules(System verilog 'module') based on instance information from SystemVerilog ASTs.
    
    Args:
        module_name (str): analyze dependencies starting from this IP module.
        
    Returns:
        dict: A dictionary containing module dependency information:
              - 'dependency_graph': A directed graph where keys are module names and values are lists of modules they depend on
              - 'instance_map': A dictionary mapping from (parent_module, instance_name) to instantiated_module
              - 'reverse_dependencies': A graph where keys are module names and values are lists of modules that depend on them
    """
    import networkx as nx
    import matplotlib.pyplot as plt
    from collections import defaultdict
    
    # Initialize data structures
    module_to_file = {}  # Maps module name to the file it's defined in
    dependency_graph = defaultdict(list)  # Maps module name to list of modules it depends on
    reverse_dependencies = defaultdict(list)  # Maps module name to list of modules that depend on it
    instance_map = {}  # Maps (parent_module, instance_name) to instantiated_module
    
    # Helper function to normalize module names
    def normalize_module_name(name):
        # Sometimes module names have parameters, so we strip those out
        return name.split('#')[0].strip()
    
    # First pass: analyze all modules or start from the specified one
    modules_to_analyze = [module_name] if module_name else list(module_dict.keys())

    for module_name in modules_to_analyze:
        try:
            # Skip modules without .sv files
            sv_files = get_svfiles_path(module_name)
        except (ValueError, FileNotFoundError):
            continue
            
        # Analyze the AST for this module
        try:
            ast_results = analyze_sv_ast_old(module_name)
        except Exception as e:
            print(f"Failed to analyze {module_name}: {str(e)}")
            continue
            
        # Process each SV file in the module
        for file_name, (modules_info, instances_info) in ast_results.items():
            # Map module names to their files
            for module_info in modules_info:
                module_name_temp = module_info['name']
                module_to_file[module_name_temp] = file_name
                
            # Process instance information to build dependency graph
            for instance_info in instances_info:
                parent_modules = [m['name'] for m in modules_info]  # The modules defined in this file
                instantiated_module = normalize_module_name(instance_info['module_name'])
                instance_name = instance_info['instance_name']
                
                for parent_module in parent_modules:
                    # Add dependency: parent_module depends on instantiated_module
                    if instantiated_module not in dependency_graph[parent_module]:
                        dependency_graph[parent_module].append(instantiated_module)
                    
                    # Add reverse dependency
                    if parent_module not in reverse_dependencies[instantiated_module]:
                        reverse_dependencies[instantiated_module].append(parent_module)
                    
                    # Map instance to its module type
                    instance_map[(parent_module, instance_name)] = instantiated_module
    
    # Convert defaultdict to regular dict for cleaner output
    dependency_graph_dict = dict(dependency_graph)
    reverse_dependencies_dict = dict(reverse_dependencies)
    
    # Create a NetworkX graph for visualization
    G = nx.DiGraph()
    
    # Add nodes and edges
    for module, dependencies in dependency_graph_dict.items():
        G.add_node(module)
        for dep in dependencies:
            G.add_edge(module, dep)
    
    # Create a reduced graph if we started with a specific module
    if module_name:
        if module_name == "prim_generic":
            return {
                'dependency_graph': dependency_graph_dict,
                'reverse_dependencies': reverse_dependencies_dict,
                'instance_map': instance_map,
                'nx_graph': {},
                'module_to_file': module_to_file
            }
        # Only include nodes that are reachable from start_module or that have a path to start_module
        reachable_nodes = set(nx.descendants(G, module_name)) | {module_name}
        nodes_with_path_to_start = set()
        for node in G.nodes():
            try:
                if nx.has_path(G, node, module_name):
                    nodes_with_path_to_start.add(node)
            except:
                pass
        
        relevant_nodes = reachable_nodes | nodes_with_path_to_start
        G_reduced = G.subgraph(relevant_nodes).copy()
    else:
        G_reduced = G
    
    return {
        'dependency_graph': dependency_graph_dict,
        'reverse_dependencies': reverse_dependencies_dict,
        'instance_map': instance_map,
        'nx_graph': G_reduced,
        'module_to_file': module_to_file
    }
analyze_module_dependencies("tlul")
# %%
def visualize_module_dependencies(dependency_results, focus_module=None, max_depth=2):
    """
    Visualize module dependencies as a graph.
    
    Args:
        dependency_results (dict): The results from analyze_module_dependencies
        focus_module (str, optional): If provided, highlight this module in the visualization
        max_depth (int, optional): Maximum depth for graph traversal from focus_module
    """
    import networkx as nx
    import matplotlib.pyplot as plt
    from matplotlib.colors import LinearSegmentedColormap
    import numpy as np
    
    G = dependency_results['nx_graph']
    
    # Create a reduced graph if focus_module is specified and max_depth is limited
    if focus_module and max_depth is not None:
        # Get nodes within max_depth of the focus module
        nodes_within_depth = {focus_module}
        current_nodes = {focus_module}
        
        # Forward traversal (what the module depends on)
        for _ in range(max_depth):
            next_nodes = set()
            for node in current_nodes:
                if node in G:
                    next_nodes.update(G.successors(node))
            current_nodes = next_nodes - nodes_within_depth
            nodes_within_depth.update(current_nodes)
        
        # Reset and do reverse traversal (what depends on the module)
        current_nodes = {focus_module}
        for _ in range(max_depth):
            next_nodes = set()
            for node in current_nodes:
                if node in G:
                    next_nodes.update(G.predecessors(node))
            current_nodes = next_nodes - nodes_within_depth
            nodes_within_depth.update(current_nodes)
        
        G_viz = G.subgraph(nodes_within_depth).copy()
    else:
        G_viz = G
    
    # Create a better layout for the graph
    if len(G_viz) > 10:
        pos = nx.spring_layout(G_viz, k=0.9, iterations=50)
    else:
        pos = nx.spring_layout(G_viz, k=1.0, iterations=50)
    
    plt.figure(figsize=(12, 10))
    
    # Set up node colors
    node_colors = []
    node_sizes = []
    
    # Custom color map - lighter to darker blue
    cmap = LinearSegmentedColormap.from_list("BlueGradient", ["#d0e0ff", "#0055aa"])
    
    # Calculate node centrality measures
    centrality = nx.betweenness_centrality(G_viz)
    max_centrality = max(centrality.values()) if centrality else 1
    
    for node in G_viz.nodes():
        if focus_module and node == focus_module:
            # Highlight the focus module
            node_colors.append("#ff5500")  # Orange
            node_sizes.append(1000)
        else:
            # Color based on centrality
            c = centrality.get(node, 0) / max_centrality if max_centrality > 0 else 0
            node_colors.append(cmap(c))
            
            # Size based on degree
            node_sizes.append(300 + 200 * (G_viz.degree(node) / max(G_viz.degree(), key=lambda x: x[1])[1]))
    
    # Draw the graph with appropriate styling
    nx.draw_networkx_nodes(G_viz, pos, 
                          node_color=node_colors, 
                          node_size=node_sizes,
                          alpha=0.8)
    
    # Draw edges with transparency based on graph density
    edge_alpha = max(0.2, min(0.7, 20 / len(G_viz.edges()))) if G_viz.edges() else 0.5
    nx.draw_networkx_edges(G_viz, pos, alpha=edge_alpha, arrows=True, 
                          arrowstyle='->', arrowsize=10, edge_color="#555555", width=1.0)
    
    # Draw labels with better font and positioned slightly above nodes
    label_pos = {k: (v[0], v[1] + 0.02) for k, v in pos.items()}
    nx.draw_networkx_labels(G_viz, label_pos, font_size=9, font_family='sans-serif')
    
    plt.title(f"Module Dependency Graph {f'(Focus: {focus_module})' if focus_module else ''}", size=16)
    plt.axis('off')
    plt.tight_layout()
    plt.show()
    
    # Print some statistics
    print(f"Graph Statistics:")
    print(f"- Total modules: {len(G)}")
    print(f"- Modules shown: {len(G_viz)}")
    print(f"- Total dependencies: {len(G.edges())}")
    print(f"- Dependencies shown: {len(G_viz.edges())}")
    
    if focus_module and focus_module in G:
        print(f"\nModule '{focus_module}' statistics:")
        print(f"- Depends on {len(list(G.successors(focus_module)))} other modules")
        print(f"- Is depended on by {len(list(G.predecessors(focus_module)))} modules")
        
        # Identify central modules
        top_modules = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:5]
        print(f"\nTop 5 most central modules:")
        for module, score in top_modules:
            print(f"- {module}: {score:.4f}")

# %%
# @tools.tool("find_module_connection_paths")
def find_module_connection_paths(dependency_results, source_module, target_module, max_paths):
    """
    Find paths in the dependency graph between source and target modules(System verilog 'module').
    
    Args:
        dependency_results (dict): Results from analyze_module_dependencies
        source_module (str): The source module name
        target_module (str): The target module name
        max_paths (int): Maximum number of paths to find
        
    Returns:
        dict: A dictionary containing found paths and path analysis
    """
    import networkx as nx
    
    G = dependency_results['nx_graph']
    
    # Check if both modules exist in the graph
    if source_module not in G or target_module not in G:
        missing = []
        if source_module not in G:
            missing.append(source_module)
        if target_module not in G:
            missing.append(target_module)
        return {
            'exists': False,
            'error': f"Modules not in graph: {', '.join(missing)}"
        }
    
    # Check if there's a path from source to target
    if not nx.has_path(G, source_module, target_module):
        # Check for reverse path as well
        if nx.has_path(G, target_module, source_module):
            return {
                'exists': True,
                'direction': 'reverse',
                'message': f"No path from {source_module} to {target_module}, but found path in reverse direction."
            }
        else:
            return {
                'exists': False,
                'message': f"No path exists between {source_module} and {target_module} in either direction."
            }
    
    # Find multiple simple paths between source and target
    try:
        # Try to find paths with nx.all_simple_paths, limiting to max_paths
        paths = list(nx.all_simple_paths(G, source_module, target_module, cutoff=10))[:max_paths]
    except nx.NetworkXError:
        # If that fails, try nx.shortest_path
        try:
            shortest_path = nx.shortest_path(G, source_module, target_module)
            paths = [shortest_path]
        except:
            paths = []
    
    # Analyze each path
    path_analysis = []
    for path in paths:
        steps = []
        for i in range(len(path) - 1):
            parent = path[i]
            child = path[i + 1]
            
            # Find instances that connect these modules
            connections = []
            for (module, instance), instantiated_module in dependency_results['instance_map'].items():
                if module == parent and instantiated_module == child:
                    connections.append(instance)
            
            steps.append({
                'from': parent,
                'to': child,
                'connecting_instances': connections
            })
        
        path_analysis.append({
            'path': path,
            'length': len(path),
            'steps': steps
        })
    
    return {
        'exists': True,
        'direction': 'forward',
        'paths_found': len(paths),
        'paths': path_analysis
    }

# # %%
# # 1. Analyze all module dependencies in the project
# all_dependencies = analyze_module_dependencies("hmac")
# print(f"Analyzed {len(all_dependencies['dependency_graph'])} modules with dependencies")

# # 2. Visualize dependencies for a specific module (e.g., hmac)
# module_of_interest = "hmac"
# print(f"\nVisualizing dependencies for module: {module_of_interest}")
# visualize_module_dependencies(all_dependencies, focus_module=module_of_interest, max_depth=2)

# # 3. Look for connections between specific modules (e.g., hmac and aes)
# source_module = "hmac"
# target_module = "prim_sha2"
# print(f"\nFinding connection paths from {source_module} to {target_module}")
# connection_paths = find_module_connection_paths(
#     all_dependencies, 
#     source_module, 
#     target_module
# )
# print(f"Connection exists: {connection_paths['exists']}")
# if connection_paths['exists'] and 'paths' in connection_paths:
#     print(f"Number of paths found: {connection_paths['paths_found']}")
    
#     # Display the shortest path
#     if connection_paths['paths']:
#         shortest = min(connection_paths['paths'], key=lambda x: x['length'])
#         print(f"\nShortest path ({shortest['length']} steps): {' -> '.join(shortest['path'])}")
        
#         print("\nDetailed path:")
#         for step in shortest['steps']:
#             instances = ', '.join(step['connecting_instances']) if step['connecting_instances'] else 'No direct instance'
#             print(f"  {step['from']} -> {step['to']} via {instances}")

# %%
