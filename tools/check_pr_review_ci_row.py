#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - tools/check_pr_review_ci_row.py
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
"""Assert that the CI-failure row of the LLM auto-review table renders as 严重 / `CI/CD` / 0.

Why this check exists
---------------------
`.github/workflows/pr-auto-review.yml` renders the review table from a Python
program embedded in a YAML block scalar (the `python3 - <<'PYEOF'` heredoc
inside the `Run LLM code review` step). Nothing else in the tree can import
that program: it only exists as text inside the workflow, so a regression in
its normalisation rules would be invisible until a real PR review came out
wrong.

That already happened once. The `严重程度 / 文件 / 行` columns used to be
written entirely by the model, which attributed a CI failure to whatever file
happened to be in the diff — PR #103 rendered the same CI failure as
`警告 / CHANGELOG.md / 12` and as `严重 / CHANGELOG.md / 1`, while PR #77 had
it right (`严重 / CI-CD / 0`). The row is now produced deterministically: any
issue whose comment mentions CI *and* a failure keyword is rewritten to
`critical` / `CI/CD` / 0, a row is appended when CI is red and the model
forgot to mention it, and the table is re-sorted afterwards.

This script extracts the embedded program from the workflow and runs it against
frozen fixtures (the real issue arrays from PR #103, the CI-downgrade path,
CI-green, model output noise, multi-line comments), asserting the full rendered
table. It needs no network, no secrets and no build.

Usage:
    python3 tools/check_pr_review_ci_row.py [path/to/pr-auto-review.yml]

Exit code 0 when every case passes, 1 otherwise.
"""
import ast
import json
import os
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_WORKFLOW = REPO / '.github' / 'workflows' / 'pr-auto-review.yml'
# The embedded program hardcodes /tmp/... paths; on Windows that resolves
# against the current drive, which is what abspath() below mirrors.
SANDBOX = pathlib.Path(os.path.abspath('/tmp'))


def extract_inline_python(workflow):
    """Return the dedented body of the `python3 - <<'PYEOF'` heredoc."""
    lines = workflow.read_text(encoding='utf-8').splitlines()
    start = next((i for i, l in enumerate(lines) if "python3 - <<'PYEOF'" in l), None)
    if start is None:
        raise SystemExit(f'FAIL: no `python3 - <<\'PYEOF\'` heredoc in {workflow}')
    indent = len(lines[start]) - len(lines[start].lstrip())
    body = []
    for line in lines[start + 1:]:
        if line.strip() == 'PYEOF':
            return '\n'.join(body)
        body.append(line[indent:] if line.startswith(' ' * indent) else line)
    raise SystemExit('FAIL: unterminated PYEOF heredoc')


MANUAL_ROW = {'severity': 'critical', 'file': '', 'line': 0, 'comment': 'MANUAL'}
CI_ROW_WARN = {'severity': 'warning', 'file': 'CHANGELOG.md', 'line': 12,
               'comment': 'CI 检查结果为 failure，必须先修复 CI 再合入。请在修复后重新触发 CI 并通过。'}
CI_ROW_CRIT = {'severity': 'critical', 'file': 'CHANGELOG.md', 'line': 1,
               'comment': 'CI 存在 failure。请审查 CI 日志定位失败原因并修复后重新触发 CI。在未确认 CI 全绿前不应合并。'}
AGPL_MCP = {'severity': 'critical', 'file': 'app/src/main/java/com/soreverse/mcp/service/McpForegroundService.kt', 'line': 1,
            'comment': '根据 AGPL-3.0-only 要求，新增或修改的源码文件必须保留/追加许可证头。'}
AGPL_CHANGELOG = {'severity': 'critical', 'file': 'CHANGELOG.md', 'line': 1,
                  'comment': '根据 AGPL-3.0-only 合规要求，新增或修改的源码/文档文件应保留或添加 AGPL 许可证头。'
                             'diff 显示 CHANGELOG.md 缺少 SPDX 版权与许可声明。'}
SCOPE_WARN = {'severity': 'warning', 'file': 'CHANGELOG.md', 'line': 12,
              'comment': '该 CHANGELOG 条目似乎描述了未在本 PR diff 中体现的功能。'}
NOTE_MCP = {'severity': 'info', 'file': 'app/src/main/java/com/soreverse/mcp/service/McpForegroundService.kt', 'line': 140,
            'comment': 'enterForeground 的注释对普通开发者较重。'}
MCP = 'app/src/main/java/com/soreverse/mcp/service/McpForegroundService.kt'

CASES = [
    {
        'name': 'PR #103 首轮：CI 行被模型降级为 warning',
        'verdict': 'request_changes', 'ci_state': 'fail', 'ci_failing': 1,
        'issues': [AGPL_MCP, CI_ROW_WARN, SCOPE_WARN, NOTE_MCP],
        'rows': [
            f'| 严重 | `{MCP}` | 1 | {AGPL_MCP["comment"]} |',
            '| 严重 | `CI/CD` | 0 | CI 检查结果为 failure，必须先修复 CI 再合入。请在修复后重新触发 CI 并通过。 |',
            '| 警告 | `CHANGELOG.md` | 12 | 该 CHANGELOG 条目似乎描述了未在本 PR diff 中体现的功能。 |',
            f'| 提示 | `{MCP}` | 140 | enterForeground 的注释对普通开发者较重。 |',
        ],
    },
    {
        'name': 'PR #103 次轮：CI 行 file/line 指向 CHANGELOG.md:1',
        'verdict': 'request_changes', 'ci_state': 'fail', 'ci_failing': 1,
        'issues': [CI_ROW_CRIT, AGPL_CHANGELOG],
        'rows': [
            '| 严重 | `CI/CD` | 0 | CI 存在 failure。请审查 CI 日志定位失败原因并修复后重新触发 CI。在未确认 CI 全绿前不应合并。 |',
            '| 严重 | `CHANGELOG.md` | 1 | 根据 AGPL-3.0-only 合规要求，新增或修改的源码/文档文件应保留或添加 AGPL 许可证头。diff 显示 CHANGELOG.md 缺少 SPDX 版权与许可声明。 |',
        ],
    },
    {
        'name': 'approve + CI 红灯：模型未写 CI 行，须补行并降级判定',
        'verdict': 'approve', 'ci_state': 'fail', 'ci_failing': 3,
        'issues': [NOTE_MCP],
        'expect_verdict': 'request_changes', 'expect_downgraded': True,
        'rows': [
            '| 严重 | `CI/CD` | 0 | CI 检查结果为 failure（共 3 项未通过），因此不批准合并，请修复 CI 失败项后重新触发 CI 并通过。 |',
            f'| 提示 | `{MCP}` | 140 | enterForeground 的注释对普通开发者较重。 |',
        ],
    },
    {
        'name': 'CI 全绿：不得出现 CI 行',
        'verdict': 'request_changes', 'ci_state': 'pass', 'ci_failing': 0,
        'issues': [SCOPE_WARN],
        'rows': ['| 警告 | `CHANGELOG.md` | 12 | 该 CHANGELOG 条目似乎描述了未在本 PR diff 中体现的功能。 |'],
    },
    {
        'name': '模型输出干扰：非字典条目、缺失 severity/file/line',
        'verdict': 'request_changes', 'ci_state': 'pass', 'ci_failing': 0,
        'issues': ['not-a-dict', MANUAL_ROW],
        'rows': ['| 严重 | `` | 0 | MANUAL |'],
    },
    {
        'name': 'comment 提到 CI 但非失败：不得改写归因',
        'verdict': 'request_changes', 'ci_state': 'pass', 'ci_failing': 0,
        'issues': [{'severity': 'info', 'file': 'test/ci-test.sh', 'line': 3,
                    'comment': '建议在 CI 中新增一步校验。'}],
        'rows': ['| 提示 | `test/ci-test.sh` | 3 | 建议在 CI 中新增一步校验。 |'],
    },
    {
        'name': '多行 comment：压成一行后再判定',
        'verdict': 'request_changes', 'ci_state': 'fail', 'ci_failing': 2,
        'issues': [{'severity': 'warning', 'file': 'docs/ci.md', 'line': 7,
                    'comment': 'CI 检查结果\n为 failure，\n请修复。'}],
        'rows': ['| 严重 | `CI/CD` | 0 | CI 检查结果 为 failure， 请修复。 |'],
    },
]


def run_case(code, case):
    """Execute the embedded program for one fixture; return (rows, verdict)."""
    SANDBOX.mkdir(parents=True, exist_ok=True)
    for stale in ('verdict.txt', 'review-body.md', 'ci-downgraded.txt'):
        (SANDBOX / stale).unlink(missing_ok=True)
    payload = {'verdict': case['verdict'], 'summary': '总体评价。', 'issues': case['issues']}
    (SANDBOX / 'llm-review-raw.txt').write_text(json.dumps(payload, ensure_ascii=False), encoding='utf-8')

    saved_env = os.environ.copy()
    os.environ['CI_STATE'] = case['ci_state']
    os.environ['CI_FAILING'] = str(case['ci_failing'])
    try:
        exec(compile(code, 'pr-auto-review-inline', 'exec'), {'__name__': '__main__'})
    except SystemExit as exc:
        if exc.code not in (0, None):
            raise AssertionError(f'embedded program exited with {exc.code}') from None
    finally:
        os.environ.clear()
        os.environ.update(saved_env)

    verdict = (SANDBOX / 'verdict.txt').read_text(encoding='utf-8').strip()
    body = (SANDBOX / 'review-body.md').read_text(encoding='utf-8')
    rows = [l for l in body.splitlines() if re.match(r'\| (?:严重|警告|提示) \|', l)]
    return rows, verdict, (SANDBOX / 'ci-downgraded.txt').exists()


def main():
    workflow = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_WORKFLOW
    code = extract_inline_python(workflow)
    ast.parse(code)  # syntax gate: a broken heredoc must fail here, not in CI
    print(f'{workflow.relative_to(REPO) if workflow.is_relative_to(REPO) else workflow}: '
          f'embedded python parsed OK ({len(code.splitlines())} lines)')

    failures = []
    for case in CASES:
        try:
            rows, verdict, downgraded = run_case(code, case)
        except AssertionError as exc:
            failures.append(f'{case["name"]}: {exc}')
            print(f'FAIL  {case["name"]}: {exc}')
            continue
        expected = case['rows']
        if rows != expected:
            failures.append(case['name'])
            print(f'FAIL  {case["name"]}')
            print('  expected: ' + '\n            '.join(expected))
            print('  actual  : ' + '\n            '.join(rows))
            continue
        if 'expect_verdict' in case and verdict != case['expect_verdict']:
            failures.append(f'{case["name"]}: verdict={verdict}')
            print(f'FAIL  {case["name"]}: verdict={verdict} != {case["expect_verdict"]}')
            continue
        if case.get('expect_downgraded') and not downgraded:
            failures.append(f'{case["name"]}: ci-downgraded marker missing')
            print(f'FAIL  {case["name"]}: ci-downgraded marker missing')
            continue
        print(f'ok    {case["name"]} ({len(rows)} rows)')

    if failures:
        print(f'\n{len(failures)}/{len(CASES)} case(s) failed')
        return 1
    print(f'\nall {len(CASES)} cases passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
