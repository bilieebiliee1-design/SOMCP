#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# init-submodules.sh — 正确初始化 third_party/*，包括 rz-ghidra 下那两个嵌套
# pin（rizinorg/ghidra 与 pugixml）。
#
# 背景：rizinorg/ghidra 是会被清洗/重写的仓。gitlink 记录的嵌套 pin 有可能
# 变成上游不存在的死提交，此时 `git submodule update --init --recursive` 的
# 表现就是：
#   fatal: remote error: upload-pack: not our ref <sha>
#   Errors during submodule fetch: third_party/rz-ghidra
# 注意失败原因是「这个提交没了」，不是「按裸 SHA 取不到」——对**可达**提交，
# `git fetch --depth 1 origin <sha>` 在这台远端本身是通的（实测 3e5d774 与
# 若干非尖端提交都成功），只有不存在的对象才回 not our ref。
#
# 本脚本的做法：
#   1) 顶层子模块用 git 自己递归 —— 它们都是干净的仓，按 SHA 取没问题；
#   2) 然后 rm 掉 rz-ghidra 下那两个嵌套目录，按 *分支名* fetch，再 detach 到
#      gitlink 里记录的 SHA。SHA 仍是权威 pin，这里只是把失败提前到有名字的
#      检核点：分支取不到时再回落一次按 SHA 的 fetch（pin 落在别的分支或 tag
#      上时仍能过），两者都失败才报错；
#   3) 逐项核对所有子模块的就位状态，最后断言 decompiler 源码在位 —— 缺了它
#      rz-ghidra 编译不出 libcore_ghidra.so，宁可在有名字的检查上失败。
#
# 顺序是有理由的：第 1 步的 `|| true` 罩住全部顶层子模块，所以**第 3 步的核对是唯一
# 的裁定点**，第 2 步不能抢在它前面 exit。第 2 步遇到「还没法判定」的状态（rz-ghidra
# 是空树、读不到它自己的 .gitmodules）只警告，让第 3 步把所有真实失败一次点名——
# 否则日志里那句 `no submodule.ghidra/ghidra.url` 会把 lief 拉不动的锅扣在
# ghidra/ghidra 头上，跑的人照着它查半天，查到的是一个没问题的子模块。
#
# 幂等：已就位则跳过。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/submodule-utils.sh
. "$ROOT/tools/submodule-utils.sh"

# 今天 rz-ghidra 的 gitlink 所指提交恰好是 rizin 分支的尖端，但这是巧合。
# 它一旦挪到别的分支或 tag，fetch_pin 会回落按 SHA 取，脚本不会因此报死。
RIZIN_GHIDRA_BRANCH="rizin"
RZ_GHIDRA_SRC="third_party/rz-ghidra"
# 嵌套项的远端。clone 用的 url 仍从 <repo>/.gitmodules 读，这两个只是「要重建、但上哪儿
# 取对象」时给调用链的一句交代（fetch_pin 的第五个参数），不参与任何判定。
# 与第三仓（third_party/rz-ghidra/.gitmodules）里写的是同一个地址。
RIZIN_GHIDRA_URL="https://github.com/rizinorg/ghidra.git"
PUGIXML_URL="https://github.com/zeux/pugixml.git"

# --- 1) 顶层子模块 ---
# 先按常规递归一次。嵌套 pin 若是死提交，这一层会失败（见上），所以 `|| true`，
# 那两个目录紧接着由第 2 步按名字重建。
# 但 `|| true` 罩住的是整条命令、也就是全部 10 个顶层子模块，所以第 3 步必须
# 逐项核对：真正的失败（lief、unicorn 之类拉不动）不能就这么被吞掉。
git submodule sync --recursive
git -c protocol.version=2 submodule update --init --recursive --force || true

# --- 2) rizin 的嵌套 pin：按分支名取，再校验 SHA ---
# ghidra/ghidra 是必需的：ghidra/CMakeLists.txt 的 decompiler 源码根指向它。
# 第五个参数（src-url）是上一次失败留下的提示：这里不知道 <repo>/<path> 从哪 clone
# （url 在 <repo> 自己的 .gitmodules 里），所以只在「真的需要重建」时说明该跑什么。
fetch_pin "$RZ_GHIDRA_SRC" "ghidra/ghidra" "$RIZIN_GHIDRA_BRANCH" "[submodules]" "$RIZIN_GHIDRA_URL"
# pugixml 没有这些问题，但统一走这条路：一处实现、一处行为。
fetch_pin "$RZ_GHIDRA_SRC" "third-party/pugixml" "master" "[submodules]" "$PUGIXML_URL"

# --- 3) 核对 + 断言 ---
# 先核对，再断言。rz-ghidra 下的两个嵌套项若在第 2 步没建成，会在这里被点名（不白名单
# 放行：放行等于宣布它们无所谓，那 marshal.cc 断言就成了唯一的裁判，报错又少了一层
# 上下文）。此后所有 `-` / `+` / `U` 都是真问题，一次点完再退出。
# 第 2 步只负责重建，裁决全在这里。
check_submodules "[submodules]"

if [ ! -f "$RZ_GHIDRA_SRC/ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/marshal.cc" ]; then
    echo "[submodules] ERROR: nested ghidra/ghidra is not populated — decompiler sources are required." >&2
    exit 1
fi
echo "[submodules] ok"
