import idaapi
import idautils
import idc
import re

methods = dict()
paths = []

def demangle_function_name(mangled_name):
    pattern = r'\?(.*?)@'
    match = re.search(pattern, mangled_name)
    if match:
        return match.group(1)
    return mangled_name

def find_function_by_partial_name(partial_name):
    if partial_name.startswith("0x"):
        base_address = idaapi.get_imagebase()
        return base_address + int(partial_name, 16)
    
    for ea, name in idautils.Names():
        if partial_name in name:
            print(f"Found: {name} at {hex(ea)}")
            return ea
    
    print(f"Function containing '{partial_name}' not found.")
    return None

def get_xrefs_to_function(function_ea, current_path):
    function_name = idc.get_func_name(function_ea)
    demangled_name = demangle_function_name(function_name)
    current_path.append(f"{demangled_name}")

    found_caller = False

    for xref in idautils.XrefsTo(function_ea):
        caller_ea = xref.frm
        caller_func = idaapi.get_func(caller_ea)

        if caller_func:
            caller_func_name = idc.get_func_name(caller_func.start_ea)
            caller_func_ea = caller_func.start_ea
            demangled_caller_name = demangle_function_name(caller_func_name)

            if hex(caller_func_ea) not in methods:
                methods[hex(caller_func_ea)] = demangled_caller_name
                found_caller = True
                new_path = current_path.copy()
                new_path[-1] += f"({hex(caller_ea)})"
                get_xrefs_to_function(caller_func_ea, new_path)
    
    if not found_caller:
        current_path[-1] += f"({hex(function_ea)})"
        paths.append(current_path)

target_function_ea = find_function_by_partial_name(idc.ARGV[1])

if target_function_ea:
    get_xrefs_to_function(target_function_ea, [])
    
    idx = 1
    with open(idc.ARGV[2], "w") as file:
        for path in paths:
            path_str = " -> ".join(reversed(path))
            print(path_str)
            # file.write(f"Path {idx}\n - ")
            file.write(path_str + "\n")
            idx += 1

else:
    print("Function not found.")

idc.Exit(0)