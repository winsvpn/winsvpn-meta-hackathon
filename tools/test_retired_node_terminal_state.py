#!/usr/bin/env python3
"""Static regressions for retired nodes as a terminal control-plane state.

The hub application is embedded in the control-plane installer.  These tests
parse that exact Python heredoc and inspect only the named function or FastAPI
endpoint under test.  They intentionally avoid whole-installer substring
counts, which can pass when an unrelated query happens to contain the expected
retirement predicate.
"""

from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROL = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
MAIN_HEADER = 'cat > "${APP_DIR}/main.py" <<\'PYEOF\''


def _embedded_hub_source() -> str:
    installer = CONTROL.read_text(encoding="utf-8")
    header_at = installer.find(MAIN_HEADER)
    if header_at < 0:
        raise AssertionError("embedded hub main.py heredoc was not found")
    body_at = installer.find("\n", header_at) + 1
    end_at = installer.find("\nPYEOF\n", body_at)
    if body_at <= 0 or end_at < 0:
        raise AssertionError("embedded hub main.py heredoc is unterminated")
    return installer[body_at:end_at]


HUB_SOURCE = _embedded_hub_source()
HUB_TREE = ast.parse(HUB_SOURCE)
FUNCTIONS = {
    node.name: node
    for node in HUB_TREE.body
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
}


def _function(name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    try:
        return FUNCTIONS[name]
    except KeyError as exc:
        raise AssertionError(f"embedded hub function is missing: {name}") from exc


def _source(node: ast.AST) -> str:
    text = ast.get_source_segment(HUB_SOURCE, node)
    if text is None:
        raise AssertionError(f"could not recover source for {type(node).__name__}")
    return text


def _string_template(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                parts.append(" {expression} ")
        return "".join(parts)
    return None


def _sql_calls(node: ast.AST) -> list[tuple[ast.Call, str]]:
    calls: list[tuple[ast.Call, str]] = []
    for candidate in ast.walk(node):
        if not (
            isinstance(candidate, ast.Call)
            and isinstance(candidate.func, ast.Attribute)
            and candidate.func.attr in {"execute", "executescript"}
            and candidate.args
        ):
            continue
        sql = _string_template(candidate.args[0])
        if sql is not None:
            calls.append((candidate, " ".join(sql.split())))
    return sorted(calls, key=lambda item: (item[0].lineno, item[0].col_offset))


def _node_sql(node: ast.AST, operation: str) -> list[tuple[ast.Call, str]]:
    pattern = re.compile(rf"\b{operation}\b.*?\bnodes\b", re.IGNORECASE)
    return [(call, sql) for call, sql in _sql_calls(node) if pattern.search(sql)]


def _calls_named(node: ast.AST, name: str) -> list[ast.Call]:
    return [
        candidate
        for candidate in ast.walk(node)
        if isinstance(candidate, ast.Call)
        and (
            (isinstance(candidate.func, ast.Name) and candidate.func.id == name)
            or (isinstance(candidate.func, ast.Attribute) and candidate.func.attr == name)
        )
    ]


def _assignment_name_for_call(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    call: ast.Call,
) -> str | None:
    parents = {
        child: parent
        for parent in ast.walk(function)
        for child in ast.iter_child_nodes(parent)
    }
    current: ast.AST = call
    while current is not function:
        current = parents[current]
        if isinstance(current, ast.Assign) and len(current.targets) == 1:
            target = current.targets[0]
            return target.id if isinstance(target, ast.Name) else None
    return None


def _assert_selection_queries_reject_retired(
    testcase: unittest.TestCase,
    function_name: str,
) -> None:
    """Require SQL exclusion or the central retired-aware policy predicate."""
    function = _function(function_name)
    queries = _node_sql(function, "SELECT")
    testcase.assertTrue(queries, f"{function_name} must query candidate nodes")
    policy_calls = _calls_named(function, "node_is_online_and_managed")
    unsafe: list[str] = []
    for call, sql in queries:
        if "retired_at IS NULL" in sql:
            continue
        assigned_name = _assignment_name_for_call(function, call)
        policy_checked = any(
            candidate.args
            and isinstance(candidate.args[0], ast.Name)
            and candidate.args[0].id == assigned_name
            for candidate in policy_calls
        )
        if not policy_checked:
            unsafe.append(f"{assigned_name or '<unbound>'}: {sql}")
    testcase.assertEqual(
        unsafe,
        [],
        f"{function_name} has fetched-node paths without SQL or policy retirement exclusion: {unsafe}",
    )


def _assert_free_selection_delegates_to_guarded_selector(
    testcase: unittest.TestCase,
    function: ast.FunctionDef | ast.AsyncFunctionDef | None = None,
) -> None:
    """Require every free-node path to use the retired-aware central selector."""

    function = function or _function("select_free_node")
    delegates = _calls_named(function, "select_online_node")
    testcase.assertTrue(delegates, "select_free_node must delegate node selection")

    safe_kwargs: set[str] = set()
    definitions: dict[str, ast.Assign] = {}
    for candidate in ast.walk(function):
        if not (
            isinstance(candidate, ast.Assign)
            and len(candidate.targets) == 1
            and isinstance(candidate.targets[0], ast.Name)
            and isinstance(candidate.value, ast.Dict)
        ):
            continue
        name = candidate.targets[0].id
        definitions[name] = candidate
        entries = {
            key.value: value
            for key, value in zip(candidate.value.keys, candidate.value.values)
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        free_only = entries.get("free_only")
        if isinstance(free_only, ast.Constant) and free_only.value is True:
            safe_kwargs.add(name)

    mutated: set[str] = set()
    for candidate in ast.walk(function):
        if isinstance(candidate, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = (
                candidate.targets
                if isinstance(candidate, ast.Assign)
                else [candidate.target]
            )
            for target in targets:
                if isinstance(target, ast.Name):
                    if target.id in safe_kwargs and candidate is not definitions[target.id]:
                        mutated.add(target.id)
                elif (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and target.value.id in safe_kwargs
                ):
                    mutated.add(target.value.id)
        if (
            isinstance(candidate, ast.Call)
            and isinstance(candidate.func, ast.Attribute)
            and isinstance(candidate.func.value, ast.Name)
            and candidate.func.value.id in safe_kwargs
        ):
            mutated.add(candidate.func.value.id)
    testcase.assertEqual(mutated, set(), "free-only selector kwargs must remain immutable")

    unsafe_calls: list[int] = []
    for call in delegates:
        direct = any(
            keyword.arg == "free_only"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in call.keywords
        )
        spread = any(
            keyword.arg is None
            and isinstance(keyword.value, ast.Name)
            and keyword.value.id in safe_kwargs
            for keyword in call.keywords
        )
        if not (direct or spread):
            unsafe_calls.append(call.lineno)
    testcase.assertEqual(
        unsafe_calls,
        [],
        f"select_free_node has central-selector calls without free_only=True: {unsafe_calls}",
    )


def _route(function: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, str]:
    routes: list[tuple[str, str]] = []
    for decorator in function.decorator_list:
        if not (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and isinstance(decorator.func.value, ast.Name)
            and decorator.func.value.id == "app"
            and decorator.args
            and isinstance(decorator.args[0], ast.Constant)
            and isinstance(decorator.args[0].value, str)
        ):
            continue
        routes.append((decorator.func.attr.upper(), decorator.args[0].value))
    if len(routes) != 1:
        raise AssertionError(
            f"expected one FastAPI route on {function.name}, found {routes}"
        )
    return routes[0]


def _assert_queries_exclude_retired(
    testcase: unittest.TestCase,
    function_name: str,
    operation: str = "SELECT",
) -> None:
    function = _function(function_name)
    queries = _node_sql(function, operation)
    testcase.assertTrue(
        queries,
        f"{function_name} must contain a scoped {operation} against nodes",
    )
    unsafe = [sql for _call, sql in queries if "retired_at IS NULL" not in sql]
    testcase.assertEqual(
        unsafe,
        [],
        f"{function_name} has {operation} node paths that do not exclude retired rows: {unsafe}",
    )


class RetiredNodeTerminalStateTests(unittest.TestCase):
    def test_central_node_policy_predicate_rejects_retired_rows(self) -> None:
        operator_policy = _function("node_is_operator_enabled")
        retired_guards = [
            candidate
            for candidate in ast.walk(operator_policy)
            if isinstance(candidate, ast.If)
            and "retired_at" in _source(candidate.test)
            and any(
                isinstance(statement, ast.Return)
                and isinstance(statement.value, ast.Constant)
                and statement.value.value is False
                for statement in candidate.body
            )
        ]
        self.assertTrue(
            retired_guards,
            "central operator policy must return false for a non-empty retired_at",
        )
        self.assertTrue(
            _calls_named(_function("node_is_online_and_managed"), "node_is_operator_enabled"),
            "online/managed policy must include the retired-aware operator predicate",
        )

    def test_smart_router_candidate_queries_exclude_retired_nodes(self) -> None:
        _assert_queries_exclude_retired(self, "smart_router_recommend_node")
        _assert_queries_exclude_retired(self, "smart_router_trigger_for_existing_node")

    def test_normal_and_free_selection_queries_exclude_retired_nodes(self) -> None:
        _assert_selection_queries_reject_retired(self, "select_online_node")
        _assert_free_selection_delegates_to_guarded_selector(self)

    def test_free_selection_delegation_rejects_guard_removal_or_mutation(self) -> None:
        source = _source(_function("select_free_node"))
        mutations = (
            source.replace('"free_only": True', '"free_only": False', 1),
            source.replace('select_online_node(conn, "auto", **shared)', 'select_online_node(conn, "auto")', 1),
            source.replace(
                'picked = select_online_node(conn, "auto", **shared)',
                'shared["free_only"] = False\n    picked = select_online_node(conn, "auto", **shared)',
                1,
            ),
        )
        for changed in mutations:
            with self.subTest(changed=changed[-180:]):
                parsed = ast.parse(changed)
                function = next(
                    node
                    for node in parsed.body
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                )
                with self.assertRaises(AssertionError):
                    _assert_free_selection_delegates_to_guarded_selector(self, function)

    def test_public_and_admin_node_listings_exclude_retired_nodes(self) -> None:
        public = _function("list_public_nodes")
        tiers = _function("admin_list_node_tiers")
        self.assertEqual(_route(public), ("GET", "/nodes"))
        self.assertEqual(_route(tiers), ("GET", "/admin/nodes/tier"))
        _assert_queries_exclude_retired(self, public.name)
        _assert_queries_exclude_retired(self, tiers.name)

    def test_heartbeat_rejects_retired_nodes_and_scopes_the_write(self) -> None:
        heartbeat = _function("heartbeat")
        heartbeat_path = _function("heartbeat_path")
        self.assertEqual(_route(heartbeat), ("POST", "/api/v1/nodes/heartbeat"))
        self.assertEqual(
            _route(heartbeat_path),
            ("POST", "/api/v1/nodes/{slug}/heartbeat"),
        )
        self.assertTrue(_calls_named(heartbeat, "node_is_retired"))
        _assert_queries_exclude_retired(self, "heartbeat", operation="UPDATE")
        self.assertTrue(
            any(
                isinstance(call.func, ast.Name) and call.func.id == "heartbeat"
                for call in ast.walk(heartbeat_path)
                if isinstance(call, ast.Call)
            ),
            "path heartbeat endpoint must delegate to the guarded heartbeat function",
        )

    def test_tier_mutations_reject_retired_nodes_before_writing(self) -> None:
        expected_routes = {
            "admin_set_node_free_access": ("POST", "/admin/nodes/free-access"),
            "admin_set_node_tier": ("POST", "/admin/nodes/tier"),
        }
        for function_name, expected_route in expected_routes.items():
            with self.subTest(function=function_name):
                function = _function(function_name)
                self.assertEqual(_route(function), expected_route)
                self.assertTrue(
                    _calls_named(function, "node_is_retired"),
                    f"{function_name} must reject a retired row before tier mutation",
                )
                selected_columns = " ".join(sql for _call, sql in _node_sql(function, "SELECT"))
                self.assertIn(
                    "retired_at",
                    selected_columns,
                    f"{function_name} cannot enforce retirement without reading retired_at",
                )

    def test_bootstrap_token_rotation_is_guarded_in_its_write_scope(self) -> None:
        bootstrap = _function("bootstrap_node")
        self.assertEqual(_route(bootstrap), ("POST", "/api/v1/nodes/bootstrap"))
        upserts = [
            (call, sql)
            for call, sql in _node_sql(bootstrap, "INSERT")
            if "ON CONFLICT" in sql and "node_token_hash" in sql
        ]
        self.assertEqual(len(upserts), 1, "bootstrap must have one scoped token upsert")
        upsert_call, _sql = upserts[0]
        enclosing = next(
            (
                candidate
                for candidate in ast.walk(bootstrap)
                if isinstance(candidate, (ast.With, ast.AsyncWith))
                and candidate.lineno <= upsert_call.lineno <= candidate.end_lineno
            ),
            None,
        )
        self.assertIsNotNone(enclosing, "bootstrap token upsert must be inside a DB scope")
        guards = _calls_named(enclosing, "node_is_retired")
        self.assertTrue(guards, "bootstrap token write scope must reject a retired row")
        self.assertLess(
            min(guard.lineno for guard in guards),
            upsert_call.lineno,
            "retirement guard must run before bootstrap token rotation",
        )

    def test_registration_upsert_rechecks_retirement_in_writer_scope(self) -> None:
        register = _function("register_node")
        self.assertEqual(_route(register), ("POST", "/api/v1/nodes/register"))
        upserts = [
            (call, sql)
            for call, sql in _node_sql(register, "INSERT")
            if "ON CONFLICT" in sql and "status=excluded.status" in sql
        ]
        self.assertEqual(len(upserts), 1, "registration must have one scoped node upsert")
        upsert_call, _sql = upserts[0]
        writer_scope = next(
            (
                candidate
                for candidate in ast.walk(register)
                if isinstance(candidate, (ast.With, ast.AsyncWith))
                and candidate.lineno <= upsert_call.lineno <= candidate.end_lineno
            ),
            None,
        )
        self.assertIsNotNone(writer_scope, "registration upsert must be inside a DB scope")
        guards = _calls_named(writer_scope, "node_is_retired")
        self.assertTrue(
            guards,
            "register_node must recheck retired_at in the authoritative writer scope, not only preflight",
        )
        self.assertLess(min(guard.lineno for guard in guards), upsert_call.lineno)

    def test_active_core_assignments_exclude_retired_exit_nodes(self) -> None:
        _assert_queries_exclude_retired(self, "active_core_assignment_payloads")

    def test_hoppy_preferred_server_validation_excludes_retired_nodes(self) -> None:
        preferred = _function("hoppy_agent_preferred_server")
        self.assertEqual(
            _route(preferred),
            ("POST", "/api/agent/v1/preferred-server"),
        )
        _assert_queries_exclude_retired(self, preferred.name)


if __name__ == "__main__":
    unittest.main()
