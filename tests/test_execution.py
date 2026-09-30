from __future__ import annotations

import sys

from ida_mcp_stdio import execution


def test_trailing_expression_and_print_are_separate():
    result = execution.execute_code("print('分析'); sum(range(5))", {})
    assert result["result"] == 10
    assert result["stdout"] == "分析\n"
    assert result["stderr"] == ""


def test_globals_persist_only_for_the_selected_namespace():
    first, second = {}, {}
    execution.execute_code("value = 41", first)
    assert execution.execute_code("value + 1", first)["result"] == 42
    assert execution.execute_code("value", second)["error"]["type"] == "NameError"


def test_nonpersistent_execution_does_not_export_names():
    namespace = {"seed": 3}
    assert (
        execution.execute_code("temporary = seed + 1; temporary", namespace, False)[
            "result"
        ]
        == 4
    )
    assert "temporary" not in namespace


def test_errors_preserve_output_and_restore_streams():
    before = sys.stdout, sys.stderr
    result = execution.execute_code("print('before'); raise ValueError('bad')", {})
    assert result["stdout"] == "before\n"
    assert result["error"]["type"] == "ValueError"
    assert (sys.stdout, sys.stderr) == before


def test_system_exit_cannot_close_the_worker():
    assert (
        execution.execute_code("raise SystemExit(2)", {})["error"]["type"]
        == "SystemExit"
    )


def test_function_style_entrypoint_receives_database():
    result = execution.execute_code("def run(db):\n    return db + 1", {"db": 5})
    assert result["result"] == 6


def test_existing_entrypoint_is_not_reinvoked_by_next_execution():
    namespace = {"db": 1}
    execution.execute_code("def run(db):\n    return db + 1", namespace)
    assert execution.execute_code("other = 3", namespace)["result"] is None


def test_output_capture_is_bounded_and_marks_truncation():
    result = execution.execute_code("print('界' * 100)", {}, output_limit=32)
    assert len(result["stdout"].encode("utf-8")) <= 32
    assert result["output_truncated"] is True


def test_result_slot_is_consumed_and_does_not_leak_to_next_call():
    namespace = {}
    assert execution.execute_code('result = {"answer": 42}', namespace)["result"] == {
        "answer": 42
    }
    assert execution.execute_code("other = 1", namespace)["result"] is None


def test_async_entrypoint_and_top_level_await():
    assert (
        execution.execute_code("async def run(db):\n    return 42", {})["result"] == 42
    )
    assert (
        execution.execute_code("import asyncio\nawait asyncio.sleep(0)\n42", {})[
            "result"
        ]
        == 42
    )
