#!/usr/bin/env python3
"""分页示例 - 展示如何处理大量函数。

Pagination（分页）是处理大量数据的技术，类似于网页分页。
"""

from ida_mcp_stdio import IDAMCPClient


def example_1_basic_pagination():
    """示例 1：基本分页"""
    print("="*60)
    print("示例 1：基本分页")
    print("="*60)
    
    with IDAMCPClient("so/libbluetooth.so") as client:
        client.initialize()
        
        # 第 1 页：前 5 个函数
        print("\n第 1 页（offset=0, count=5）:")
        page1 = client.list_funcs(offset=0, count=5)
        print(f"总数: {page1['total']}")
        print(f"返回: {page1['count']}")
        print(f"还有更多: {page1['more']}")
        for f in page1['data']:
            print(f"  {f['addr']} {f['name']}")
        
        # 第 2 页：接下来 5 个函数
        print("\n第 2 页（offset=5, count=5）:")
        page2 = client.list_funcs(offset=5, count=5)
        print(f"返回: {page2['count']}")
        for f in page2['data']:
            print(f"  {f['addr']} {f['name']}")
        
        # 第 3 页：再接下来 5 个函数
        print("\n第 3 页（offset=10, count=5）:")
        page3 = client.list_funcs(offset=10, count=5)
        print(f"返回: {page3['count']}")
        for f in page3['data']:
            print(f"  {f['addr']} {f['name']}")


def example_2_get_all_functions():
    """示例 2：获取所有函数（使用分页）"""
    print("\n" + "="*60)
    print("示例 2：获取所有函数")
    print("="*60)
    
    with IDAMCPClient("so/libbluetooth.so") as client:
        client.initialize()
        
        all_funcs = []
        offset = 0
        batch_size = 100  # 每次获取 100 个
        
        print(f"\n使用分页获取所有函数（每批 {batch_size} 个）...")
        
        while True:
            # 获取一批函数
            funcs = client.list_funcs(offset=offset, count=batch_size)
            all_funcs.extend(funcs['data'])
            
            print(f"  已获取: {len(all_funcs)}/{funcs['total']}")
            
            # 如果没有更多，退出
            if not funcs['more']:
                break
            
            # 移动到下一批
            offset += batch_size
        
        print(f"\n✅ 总共获取了 {len(all_funcs)} 个函数")
        
        # 显示前 10 个和后 10 个
        print("\n前 10 个函数:")
        for f in all_funcs[:10]:
            print(f"  {f['addr']} {f['name']}")
        
        print("\n后 10 个函数:")
        for f in all_funcs[-10:]:
            print(f"  {f['addr']} {f['name']}")


def example_3_search_with_pagination():
    """示例 3：搜索特定函数（带分页）"""
    print("\n" + "="*60)
    print("示例 3：搜索特定函数")
    print("="*60)
    
    with IDAMCPClient("so/libbluetooth.so") as client:
        client.initialize()
        
        # 搜索所有包含 "gatt" 的函数
        print("\n搜索包含 'gatt' 的函数...")
        funcs = client.list_funcs(filter="*gatt*", count=20)
        
        print(f"找到: {funcs['total']} 个匹配的函数")
        print(f"显示前 {len(funcs['data'])} 个:")
        
        for i, f in enumerate(funcs['data'], 1):
            print(f"  {i:2d}. {f['addr']} {f['name'][:60]}")
        
        if funcs['more']:
            print(f"\n... 还有 {funcs['total'] - len(funcs['data'])} 个匹配的函数")
            print("提示：增加 count 参数可以看到更多结果")


def example_4_why_pagination():
    """示例 4：为什么需要分页？"""
    print("\n" + "="*60)
    print("示例 4：为什么需要分页？")
    print("="*60)
    
    with IDAMCPClient("so/libbluetooth.so") as client:
        client.initialize()
        
        # 获取总数
        funcs = client.list_funcs(count=1)
        total = funcs['total']
        
        print(f"\n这个二进制文件有 {total:,} 个函数")
        print(f"\n如果一次性获取所有函数：")
        print(f"  - 数据量：约 {total * 100 / 1024:.1f} KB")
        print(f"  - 传输时间：可能需要几秒")
        print(f"  - 内存占用：较大")
        
        print(f"\n使用分页（每次 100 个）：")
        print(f"  - 数据量：约 {100 * 100 / 1024:.1f} KB 每批")
        print(f"  - 传输时间：毫秒级")
        print(f"  - 内存占用：小")
        print(f"  - 可以按需获取，不需要全部加载")
        
        print("\n✅ 分页的好处：")
        print("  1. 快速响应 - 不需要等待所有数据")
        print("  2. 节省内存 - 只加载需要的部分")
        print("  3. 灵活控制 - 可以随时停止")
        print("  4. 更好的用户体验 - 可以边加载边显示")


def example_5_filter_vs_pagination():
    """示例 5：过滤 vs 分页"""
    print("\n" + "="*60)
    print("示例 5：过滤 vs 分页")
    print("="*60)
    
    with IDAMCPClient("so/libbluetooth.so") as client:
        client.initialize()
        
        # 过滤：只返回匹配的函数
        print("\n1. 使用过滤（filter）:")
        print("   只返回名字匹配的函数")
        funcs = client.list_funcs(filter="*bte_*", count=10)
        print(f"   找到 {funcs['total']} 个匹配 '*bte_*' 的函数")
        for f in funcs['data'][:5]:
            print(f"     {f['addr']} {f['name']}")
        
        # 分页：返回所有函数的一部分
        print("\n2. 使用分页（offset/count）:")
        print("   返回所有函数的第 100-110 个")
        funcs = client.list_funcs(offset=100, count=10)
        print(f"   总共 {funcs['total']} 个函数，显示第 100-110 个:")
        for i, f in enumerate(funcs['data'], 100):
            print(f"     {i:3d}. {f['addr']} {f['name'][:50]}")
        
        # 组合使用
        print("\n3. 组合使用（filter + pagination）:")
        print("   搜索 '*gatt*'，显示第 10-20 个结果")
        funcs = client.list_funcs(filter="*gatt*", offset=10, count=10)
        print(f"   找到 {funcs['total']} 个匹配的函数")
        print(f"   显示第 10-20 个:")
        for i, f in enumerate(funcs['data'], 10):
            print(f"     {i:2d}. {f['addr']} {f['name'][:50]}")


if __name__ == "__main__":
    print("="*60)
    print("分页（Pagination）示例")
    print("="*60)
    print("\nPagination 是处理大量数据的技术，类似于网页分页。")
    print("当有 13,387 个函数时，不能一次性全部获取。")
    print()
    
    # 运行所有示例
    example_1_basic_pagination()
    example_2_get_all_functions()
    example_3_search_with_pagination()
    example_4_why_pagination()
    example_5_filter_vs_pagination()
    
    print("\n" + "="*60)
    print("所有示例完成！")
    print("="*60)
