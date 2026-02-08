#!/usr/bin/env python3
"""测试特定函数的反编译和分析。

这个脚本展示如何测试特定的 C++ 函数，包括：
- 搜索函数
- 反编译
- 反汇编
- 查看交叉引用
- 查看调用关系

Usage:
    # 测试特定函数
    python examples/mcp_tools/test_specific_function.py so/libbluetooth.so "gatt::DatabaseBuilder::AddService"
    
    # 使用修饰名
    python examples/mcp_tools/test_specific_function.py so/libbluetooth.so "_ZN4gatt15DatabaseBuilder10AddServiceEttRKN9bluetooth4UuidEb"
    
    # 使用通配符搜索
    python examples/mcp_tools/test_specific_function.py so/libbluetooth.so "*DatabaseBuilder*AddService*"
"""

import sys
from pathlib import Path


def test_specific_function(client, function_name):
    """测试特定函数的所有分析功能。"""
    
    print("="*60)
    print(f"测试函数: {function_name}")
    print("="*60)
    
    # 1. 搜索函数
    print("\n1. 搜索函数...")
    if "*" in function_name or "?" in function_name:
        # 使用通配符搜索
        funcs = client.list_funcs(filter=function_name, count=10)
    else:
        # 精确搜索（尝试作为修饰名或普通名）
        funcs = client.list_funcs(filter=f"*{function_name}*", count=10)
    
    if not funcs.get("data"):
        print(f"❌ 未找到函数: {function_name}")
        print("\n提示：")
        print("  - C++ 函数名可能被修饰，尝试使用通配符: *函数名*")
        print("  - 使用 --list 查看所有函数")
        print("  - 使用 --search 搜索函数")
        return False
    
    print(f"✅ 找到 {len(funcs['data'])} 个匹配的函数：")
    for func in funcs["data"]:
        print(f"  {func['addr']:12s} {func['name']:60s} (size: {func.get('size', '?')})")
    
    # 使用第一个匹配的函数
    target_func = funcs["data"][0]
    addr = target_func["addr"]
    name = target_func["name"]
    
    print(f"\n将测试函数: {name}")
    print(f"地址: {addr}")
    
    # 2. 反编译
    print("\n" + "="*60)
    print("2. 反编译函数")
    print("="*60)
    result = client.decompile(addr)
    
    if result.get("error"):
        print(f"❌ 反编译失败: {result['error']}")
    elif result.get("code"):
        code = result["code"]
        print(f"✅ 反编译成功！代码长度: {len(code)} 字符")
        
        # 显示前 50 行
        lines = code.split('\n')
        print(f"\n前 {min(50, len(lines))} 行代码：")
        print("-"*60)
        for i, line in enumerate(lines[:50], 1):
            print(f"{i:3d} | {line}")
        
        if len(lines) > 50:
            print(f"... 还有 {len(lines) - 50} 行")
        print("-"*60)
    else:
        print("⚠️  未返回代码")
    
    # 3. 反汇编
    print("\n" + "="*60)
    print("3. 反汇编函数（前 20 条指令）")
    print("="*60)
    result = client.disasm(addr, max_instructions=20)
    
    if result.get("error"):
        print(f"❌ 反汇编失败: {result['error']}")
    elif result.get("lines"):
        lines = result["lines"]
        print(f"✅ 反汇编成功！共 {len(lines)} 条指令")
        print()
        for line in lines:
            print(f"  {line['addr']:12s} {line['text']}")
        
        if result.get("function"):
            print(f"\n函数名: {result['function']}")
    else:
        print("⚠️  未返回反汇编")
    
    # 4. 交叉引用
    print("\n" + "="*60)
    print("4. 查看交叉引用（谁调用了这个函数）")
    print("="*60)
    result = client.xrefs_to(addr, limit=20)
    
    if result and len(result) > 0:
        xrefs = result[0].get("xrefs", [])
        if xrefs:
            print(f"✅ 找到 {len(xrefs)} 个交叉引用：")
            for xref in xrefs[:10]:
                fn_info = xref.get("fn", {})
                fn_name = fn_info.get("name", "unknown") if fn_info else "unknown"
                print(f"  {xref['addr']:12s} ({xref['type']:6s}) from {fn_name}")
            
            if len(xrefs) > 10:
                print(f"  ... 还有 {len(xrefs) - 10} 个引用")
            
            if result[0].get("more"):
                print(f"  (还有更多引用未显示)")
        else:
            print("⚠️  未找到交叉引用")
    else:
        print("⚠️  未返回结果")
    
    # 5. 被调用函数
    print("\n" + "="*60)
    print("5. 查看被调用函数（这个函数调用了谁）")
    print("="*60)
    result = client.callees(addr, limit=20)
    
    if result and len(result) > 0:
        callees = result[0].get("callees", [])
        if callees:
            print(f"✅ 找到 {len(callees)} 个被调用函数：")
            for callee in callees[:10]:
                print(f"  {callee['addr']:12s} {callee['name']:50s} ({callee['type']})")
            
            if len(callees) > 10:
                print(f"  ... 还有 {len(callees) - 10} 个被调用函数")
            
            if result[0].get("more"):
                print(f"  (还有更多被调用函数未显示)")
        else:
            print("⚠️  未找到被调用函数")
    else:
        print("⚠️  未返回结果")
    
    # 6. 函数信息摘要
    print("\n" + "="*60)
    print("6. 函数信息摘要")
    print("="*60)
    print(f"函数名: {name}")
    print(f"地址: {addr}")
    print(f"大小: {target_func.get('size', '?')} 字节")
    
    # 重新获取反编译结果来显示行数
    decompile_result = client.decompile(addr)
    if decompile_result.get("code"):
        print(f"伪代码行数: {len(decompile_result['code'].split(chr(10)))} 行")
    
    print("\n✅ 测试完成！")
    return True


def main():
    if len(sys.argv) < 3:
        print("Usage: python test_specific_function.py <binary_path> <function_name>")
        print()
        print("Examples:")
        print("  # 使用 C++ 函数名（会自动搜索）")
        print("  python test_specific_function.py binary.so 'gatt::DatabaseBuilder::AddService'")
        print()
        print("  # 使用修饰名")
        print("  python test_specific_function.py binary.so '_ZN4gatt15DatabaseBuilder10AddServiceEttRKN9bluetooth4UuidEb'")
        print()
        print("  # 使用通配符")
        print("  python test_specific_function.py binary.so '*DatabaseBuilder*AddService*'")
        print()
        print("  # 使用地址")
        print("  python test_specific_function.py binary.so '0x4cd474'")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    function_name = sys.argv[2]
    
    if not Path(binary_path).exists():
        print(f"Error: File not found: {binary_path}")
        sys.exit(1)
    
    from ida_mcp_stdio import IDAMCPClient
    
    print("="*60)
    print("特定函数分析工具")
    print("="*60)
    print(f"二进制文件: {binary_path}")
    print(f"目标函数: {function_name}")
    
    with IDAMCPClient(binary_path, verbose=False) as client:
        client.initialize()
        test_specific_function(client, function_name)
    
    print("\n" + "="*60)
    print("分析完成！")
    print("="*60)


if __name__ == "__main__":
    main()
