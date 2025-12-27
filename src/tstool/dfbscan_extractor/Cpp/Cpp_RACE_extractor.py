from tstool.analyzer.TS_analyzer import *
from tstool.analyzer.Cpp_TS_analyzer import *
from ..dfbscan_extractor import *


class Cpp_RACE_extractor(DFBScanExtractor):
    def extract_sources(self, function: Function) -> List[Value]:
        """
        Extract potential shared resources or thread creation points as sources.
        1. Static variables (shared across function calls/threads).
        2. Arguments passed to thread creation functions (std::thread, pthread_create).
        """
        root_node = function.parse_tree_root_node
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        file_path = function.file_path
        
        sources = []
        
        # 1. Find static variables
        declarations = find_nodes_by_type(root_node, "declaration")
        for decl in declarations:
            is_static = False
            for child in decl.children:
                if child.type == "storage_class_specifier" and source_code[child.start_byte:child.end_byte] == "static":
                    is_static = True
                    break
            
            if is_static:
                init_declarators = find_nodes_by_type(decl, "init_declarator")
                for init_decl in init_declarators:
                    declarator = init_decl.child_by_field_name("declarator")
                    # Handle pointer declarators etc.
                    while declarator.type in ["pointer_declarator", "reference_declarator"]:
                        declarator = declarator.child_by_field_name("declarator")
                        
                    if declarator and declarator.type == "identifier":
                        name = source_code[declarator.start_byte:declarator.end_byte]
                        line_number = source_code[:declarator.start_byte].count("\n") + 1
                        sources.append(Value(name, line_number, ValueLabel.SRC, file_path))

        # 2. Find arguments to thread creation
        call_expressions = find_nodes_by_type(root_node, "call_expression")
        for call in call_expressions:
            func_node = call.child_by_field_name("function")
            if func_node:
                func_name = source_code[func_node.start_byte:func_node.end_byte]
                # Simple heuristic for thread creation
                if "thread" in func_name or "async" in func_name: 
                    args = call.child_by_field_name("arguments")
                    if args:
                        for arg in args.children:
                            if arg.type == "identifier":
                                name = source_code[arg.start_byte:arg.end_byte]
                                line_number = source_code[:arg.start_byte].count("\n") + 1
                                sources.append(Value(name, line_number, ValueLabel.SRC, file_path))
                            elif arg.type == "reference_expression": # std::ref(x)
                                for child in arg.children:
                                    if child.type == "identifier":
                                        name = source_code[child.start_byte:child.end_byte]
                                        line_number = source_code[:child.start_byte].count("\n") + 1
                                        sources.append(Value(name, line_number, ValueLabel.SRC, file_path))
        
        return sources

    def extract_sinks(self, function: Function) -> List[Value]:
        """
        Extract potential sinks for Race Condition (Write/Read operations).
        We focus on modifications (assignments, increments) as primary sinks.
        """
        root_node = function.parse_tree_root_node
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        file_path = function.file_path
        
        sinks = []
        
        # 1. Assignments
        assignments = find_nodes_by_type(root_node, "assignment_expression")
        for assign in assignments:
            left = assign.child_by_field_name("left")
            if left:
                # Extract the identifier being assigned to
                # This might be complex (e.g., *ptr = val, arr[i] = val)
                # For simplicity, we take the text of the left side if it's an identifier or simple expression
                name = source_code[left.start_byte:left.end_byte]
                line_number = source_code[:left.start_byte].count("\n") + 1
                sinks.append(Value(name, line_number, ValueLabel.SINK, file_path))

        # 2. Update expressions (++, --)
        updates = find_nodes_by_type(root_node, "update_expression")
        for update in updates:
            arg = update.child_by_field_name("argument")
            if arg:
                name = source_code[arg.start_byte:arg.end_byte]
                line_number = source_code[:arg.start_byte].count("\n") + 1
                sinks.append(Value(name, line_number, ValueLabel.SINK, file_path))
                
        return sinks
