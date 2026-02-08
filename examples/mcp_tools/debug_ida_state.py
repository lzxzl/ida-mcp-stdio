#!/usr/bin/env python3
"""Debug IDA state directly using idalib.

This script opens the database directly and checks what IDA sees.
"""

import os
import sys
from pathlib import Path


def auto_detect_idadir():
    """Auto-detect IDA installation directory."""
    import platform
    system = platform.system()
    candidates = []
    
    if system == "Darwin":
        applications = Path("/Applications")
        if applications.exists():
            for app in sorted(applications.glob("IDA*.app"), reverse=True):
                macos_dir = app / "Contents" / "MacOS"
                if (macos_dir / "libidalib.dylib").exists():
                    candidates.append(str(macos_dir))
    elif system == "Linux":
        for base in ["/opt/idapro", "/opt/ida", Path.home() / "idapro", Path.home() / "ida"]:
            p = Path(base)
            if (p / "libidalib.so").exists() or (p / "idat64").exists():
                candidates.append(str(p))
    elif system == "Windows":
        for pf in [os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", "")]:
            if not pf:
                continue
            pf_path = Path(pf)
            if pf_path.exists():
                for d in sorted(pf_path.glob("IDA*"), reverse=True):
                    if (d / "idalib.dll").exists() or (d / "idat64.exe").exists():
                        candidates.append(str(d))
    
    if candidates:
        return candidates[0]
    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python debug_ida_state.py <binary_path>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    if not Path(binary_path).exists():
        print(f"Error: File not found: {binary_path}")
        sys.exit(1)
    
    # Auto-detect IDADIR if not set
    if "IDADIR" not in os.environ:
        idadir = auto_detect_idadir()
        if idadir:
            os.environ["IDADIR"] = idadir
            print(f"Auto-detected IDADIR: {idadir}\n")
        else:
            print("Warning: Could not auto-detect IDADIR")
    
    print("="*60)
    print("IDA State Debug")
    print("="*60)
    print(f"Binary: {binary_path}\n")
    
    try:
        import idapro
        print("1. Opening database...")
        
        # Check if database files exist
        db_path = Path(binary_path)
        has_existing_db = (
            db_path.with_suffix('.idb').exists() or
            db_path.with_suffix('.i64').exists() or
            Path(str(db_path) + '.idb').exists() or
            Path(str(db_path) + '.i64').exists() or
            Path(str(db_path) + '.id0').exists()
        )
        
        if has_existing_db:
            print(f"   Found existing database files")
            # Try to find the actual database file
            if Path(str(db_path) + '.idb').exists():
                db_file = str(db_path) + '.idb'
                print(f"   Using .idb file: {db_file}")
            elif Path(str(db_path) + '.i64').exists():
                db_file = str(db_path) + '.i64'
                print(f"   Using .i64 file: {db_file}")
            elif Path(str(db_path) + '.id0').exists():
                # For old format, still use the binary path
                db_file = str(binary_path)
                print(f"   Using old format (.id0/.id1/.id2)")
            else:
                db_file = str(binary_path)
            
            print(f"   Opening in read mode (False)...")
            idapro.open_database(db_file, False)  # False = open existing
        else:
            print(f"   No existing database")
            print(f"   Creating new database (True)...")
            idapro.open_database(str(binary_path), True)  # True = create new
        
        print("   ✅ Database opened\n")
        
        print("2. Waiting for auto-analysis...")
        import ida_auto
        ida_auto.auto_wait()
        print("   ✅ Auto-analysis completed\n")
        
        print("3. Checking database info...")
        import ida_ida
        import ida_nalt
        
        min_ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()
        print(f"   Min EA: {hex(min_ea)}")
        print(f"   Max EA: {hex(max_ea)}")
        print(f"   Range: {max_ea - min_ea} bytes")
        
        file_type = ida_ida.inf_get_filetype()
        print(f"   File type: {file_type}")
        
        input_file = ida_nalt.get_input_file_path()
        print(f"   Input file: {input_file}\n")
        
        print("4. Counting functions...")
        import idautils
        func_count = 0
        for ea in idautils.Functions():
            func_count += 1
        print(f"   Total functions: {func_count}\n")
        
        if func_count > 0:
            print("5. First 10 functions:")
            import ida_funcs
            count = 0
            for ea in idautils.Functions():
                name = ida_funcs.get_func_name(ea)
                fn = ida_funcs.get_func(ea)
                size = fn.size() if fn else 0
                print(f"   {hex(ea):12s} {name:40s} (size: {size})")
                count += 1
                if count >= 10:
                    break
        else:
            print("5. No functions found!")
            print("\n6. Checking segments...")
            import ida_segment
            for n in range(ida_segment.get_segm_qty()):
                seg = ida_segment.getnseg(n)
                if seg:
                    name = ida_segment.get_segm_name(seg)
                    print(f"   Segment {n}: {name} [{hex(seg.start_ea)} - {hex(seg.end_ea)}]")
            
            print("\n7. Checking if any code exists...")
            import ida_bytes
            ea = min_ea
            code_count = 0
            for _ in range(100):
                if ida_bytes.is_code(ida_bytes.get_flags(ea)):
                    code_count += 1
                ea = ida_bytes.next_head(ea, max_ea)
                if ea == ida_ida.BADADDR:
                    break
            print(f"   Found {code_count} code addresses in first 100 items")
        
        print("\n" + "="*60)
        print("Debug completed!")
        print("="*60)
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
