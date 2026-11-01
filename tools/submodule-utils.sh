#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# submodule-utils.sh — init-submodules.sh 与 build-rz-ghidra-android.sh 共用的
# 子模块工具函数。source 进来用，不单独执行。
#
# 两处脚本都要「按分支名取对象、再本地校验 gitlink 的 SHA」，这份实现只写一遍：
# 上一版是两套代码，很快就开始漂移（一个无条件 fetch 一个按需，输出格式、
# 错误前缀、溯源提示各不相同），排查时日志对不上号。

# heal_submodule_checkout <repo> <prefix>
#   把「空壳 checkout」的 <repo> 落到它**父仓 gitlink 记录的**那个提交上，然后才读它的
#   .gitmodules。必须直接调用。
#
#   触发场景：顶层 `git submodule update` 中途死在别的子模块上。git 会把已经 clone 过的
#   <repo> 留在它自己当时的位置上（实测：停在 b97171a，不是 gitlink 的 999df7b）、工作树
#   是空的（只剩一个 .git 指针文件）。这时 <repo>/.gitmodules 读不到，任何「读
#   <repo>/.gitmodules 取 url」的逻辑都会把失败归因到 <repo> 里面的东西 —— 而真正的原因
#   是别的子模块没拉下来。
#
#   落点是**父仓的 gitlink**，不是 <repo> 自己的 HEAD。这一点是硬要求：如果按自己的 HEAD
#   自愈，<repo> 就停在一个 git 随手留下的提交上，后面读到的嵌套 pin 全是那棵树的，
#   而真正该编译的是父仓钉的那棵树 —— 校验与编译又成了两棵树。
#
#   判据必须是「工作树是空的」，不能只看 .gitmodules：一个内容本来就没有 .gitmodules 的
#   仓也会命中，那时工作树完好，不该动。也不能用 `ls-tree`（读 HEAD 的树）或 `ls-files`
#   （读索引）——工作树被清空后两者照样列出全部路径。
#
#   对象不在才补一次 fetch；仍失败只警告 —— 真正的裁定权在后面那一轮逐项核对。
heal_submodule_checkout() {
    local repo="$1" prefix="$2" want
    # 空壳 = 有 .git、工作树里除 .git 之外一个文件都没有。用 find 而不是 ls -A：交叉
    # 平台的 ls 对隐藏文件的行为不一致，而这里错一次就会把一个完好的工作树 checkout 掉。
    if [ -n "$(find "$repo" -mindepth 1 -maxdepth 1 ! -name .git -print -quit 2>/dev/null || true)" ]; then
        return 0
    fi
    # pin 只能从父仓的 gitlink 读：<repo> 自己的 HEAD 是 git 随手留下的位置，不是事实来源。
    want="$(git ls-tree HEAD -- "$repo" 2>/dev/null | awk '$1 == "160000" { print $3 }' || true)"
    if [ -z "$want" ]; then
        echo "$prefix WARN: $repo is an empty shell and HEAD records no gitlink for it (run from the" >&2
        echo "$prefix repo root, or let tools/init-submodules.sh do it); leaving the pin check to the end." >&2
        return 0
    fi
    echo "$prefix $repo is an empty shell; checking it out at the superproject pin $want before reading its .gitmodules" >&2
    # 不加 --force：空壳里没有可丢的东西，加了只会在误判时把用户的工作树一起抹掉。
    if ! git -C "$repo" checkout --quiet --detach "$want" 2>/dev/null; then
        # 对象不全（--filter=blob:none 的 partial clone 或浅克隆）时才需要走网络。
        git -C "$repo" fetch --quiet origin "$want" 2>/dev/null || true
        if ! git -C "$repo" checkout --quiet --detach "$want" 2>/dev/null; then
            echo "$prefix WARN: could not populate $repo at $want; continuing — the check at the end will report it." >&2
        fi
    fi
}

# pin_of <repo> <path> <prefix>
#   打印 <repo> 里 HEAD 记录的 <path> gitlink SHA；没有就报错退出。
#
#   必须直接调用，不要放进 $( ) 或管道：函数里用 exit 1 报错，而 exit 只终止当前
#   shell —— 在命令替换里它退的是那个子 shell，父进程拿到空串继续跑，失败就被降级
#   成一句没有归因的空值错误。本文件所有以 exit 1 表达失败的函数（pin_of、
#   fetch_pin、check_submodules）都遵守这条约定，调用点也一律直接调用。
#   这是「pin 从哪来」的唯一入口：fetch_pin 与 build-rz-ghidra-android.sh 的兜底
#   clone 都走它。
#
#   这里**故意没有**「回落 pin」。上一版试过：<repo> 自己的 HEAD 里没有这条 gitlink 时
#   改用父仓 HEAD 的那份。但父仓那份和 <repo> 的 HEAD 不是同一个东西 —— <repo> 停在
#   别的提交上时，它的树里根本没有这条 gitlink，此时拿父仓的 pin 去 clone，就等于
#   用一棵树的 pin 覆盖另一棵树的判断，失败被抹平成一个「成功」。父仓的 gitlink 只在
#   一个地方用：heal_submodule_checkout 把空壳 <repo> 落到那个提交上。落到那儿之后，
#   pin 自然从 <repo> 自己的 HEAD 读得到，没有第二份。
#
#   不写成 `x="$(git rev-parse "HEAD:$path")"`：`set -e` 对赋值里的命令替换是失效的。
#   `git rev-parse HEAD:<缺失路径>` 会当场 exit 128，而赋值仍然成功、脚本带着空串
#   继续往下跑（实测 bash 5.2：`set -euo pipefail; v="$(git rev-parse HEAD:nope)"
#   ; echo alive` 会打印 alive，退出码还是 128）。那之后 `checkout --detach ""`
#   只剩一句 `invalid reference: `——恰好是不可归因的失败。
#   所以这里显式核对输出：先确认 HEAD 里这一项是 gitlink（160000），再看 rev-parse
#   给的是不是 40/64 位十六进制长 SHA。空串、git 自带的致命输出、路径回显（路径
#   不存在时 rev-parse 原样把 HEAD:<path> 打到 stdout）、普通目录的 tree SHA 都不算 pin。
pin_of() {
    local repo="$1" path="$2" prefix="$3" out want
    out="$(git -C "$repo" ls-tree HEAD -- "$path" 2>/dev/null || true)"
    case "$out" in
        160000\ commit\ *)
            ;;
        *)
            echo "$prefix ERROR: HEAD of $repo records no gitlink (submodule) for $path" >&2
            echo "$prefix That means $repo is not at the commit the superproject pins. Run" >&2
            echo "$prefix tools/init-submodules.sh from the repo root (it checks it out at the gitlink)," >&2
            echo "$prefix or bump the submodule pin so HEAD points at an existing commit." >&2
            exit 1
            ;;
    esac
    out="$(git -C "$repo" rev-parse "HEAD:$path" 2>/dev/null || true)"
    want="$(printf '%s\n' "$out" | tail -1)"
    case "$want" in
        '' | fatal:* | *"Not a valid object name"* | *:*)
            echo "$prefix ERROR: HEAD of $repo records no gitlink (submodule) for $path" >&2
            echo "$prefix Run tools/init-submodules.sh from the repo root, or bump the submodule pin." >&2
            exit 1
            ;;
    esac
    if ! printf '%s' "$want" | grep -Eq '^[0-9a-f]{40}([0-9a-f]{24})?$'; then
        echo "$prefix ERROR: unexpected gitlink pin '$want' for $repo/$path" >&2
        exit 1
    fi
    printf '%s\n' "$want"
}

# fetch_pin <repo> <path> <branch> <prefix> [src-url]
#   把 <repo>/<path> 置备到 <repo> 的 HEAD 记录的 gitlink SHA（由 pin_of 读）。
#   取对象的主路径是「按分支名 fetch」再本地校验 SHA —— pin 仍是权威，改的只是怎么
#   把对象搬下来。不直接按 SHA 请求，是因为 rizinorg/ghidra 会把 pin 指向的提交清洗
#   掉，那时远端只回一句 `not our ref`；按名字取 + 本地校验把失败落在有名字的检核点
#   上，并给出处置指引。注意这是为了定位死 pin，不是「裸 SHA 取不到」：对可达提交，
#   按裸 SHA 的 fetch 本身是通的。
#   `branch` 只提示「哪条历史」，不是 pin 的一部分：分支上取不到（pin 落在别的分支或
#   tag 上）就回落一次按 SHA 的 fetch，两者都失败才算失败。
#   日志前缀 <prefix> 由调用方给（[submodules] / [rz-ghidra]）。
#   可选的 <src-url> 只是把「上哪儿去抬 gitlink / 改 tag」这句话说得具体（[rz-ghidra]
#   的兜底 clone 知道 <repo> 从哪来，就传进来）。它不参与任何判定。
#
#   必须直接调用（同 pin_of）：失败用 exit 1 表达，放进 $( ) 会被子 shell 吃掉。
#
#   <repo> 本身可能是一个「空壳」的 gitlink checkout —— 也就是这一步要救的那个场景：
#   顶层 `submodule update` 失败后，git 会把 <repo> 留在自己的位置上，工作树却是空的。
#   那就先把它落到**父仓 gitlink 记录的**提交上（heal_submodule_checkout），再读 pin。
#   落不下去（父仓也没有这条 gitlink）时打印一笔带名字的 skip、`return 0`，交给调用方
#   最后的 check_submodules 逐项裁决 —— 那时顶层子模块的失败会被点名，指向的才是真正
#   的元凶。不做第 2 条的 `exit 1`，正是为了不让报错指向 ghidra/ghidra 而真实原因是 lief。
#
#   重建走「先建到 <repo>/<path>.tmp.$$，成功才换名」：clone 失败时别把 <repo> 的整个
#   工作树清空。老写法是 `rm -rf <repo>/<path>` 再 clone，一旦 clone/fetch 死在半路，
#   丢掉的不只是一个目录 —— <repo> 是本地构建的源本体（不在 CI 的 actions/checkout
#   里），没有第二份，用户在该目录里的改动也一并没了。原子换名的代价是 mv 期间两个
#   目录各占一份磁盘，接受的正是这个。
#
#   临时目录不用 EXIT trap 清理：EXIT trap 是单槽位，本函数里设一个会把调用方的
#   （build-rz-ghidra-android.sh 兜底 clone 那个）覆盖掉且不还原。改用显式清理。
fetch_pin() {
    local repo="$1" path="$2" branch="$3" prefix="$4" src_url="${5:-}"
    local want url tmp

    heal_submodule_checkout "$repo" "$prefix"
    # pin_of 用 exit 1 报错、必须直接调用，但它把 pin 打到 stdout —— 用重定向接住，
    # 不用 $( )：$( ) 里 exit 只退子 shell，父进程会拿到空串继续跑（就是本文件开头
    # 反复警告的那个坑）。stdout 走临时文件，报错照旧从 stderr 出来。
    local pin_file
    pin_file="$(mktemp)"
    pin_of "$repo" "$path" "$prefix" >"$pin_file"
    want="$(cat "$pin_file")"
    rm -f "$pin_file"

    # 目录可能是 gitlink checkout（.git 是文件），也可能是本地独立 clone
    # （.git 是目录）。两种都算「已就位」，否则每次都会白删白拉。
    if [ -e "$repo/$path/.git" ] &&
        [ "$(git -C "$repo/$path" rev-parse HEAD 2>/dev/null || true)" = "$want" ]; then
        echo "$prefix $path already at $want"
        return 0
    fi

    # <repo>/.gitmodules 缺失或没写这条：不是「目录坏到只能删」，是拼不出 clone 的 url。
    # 这时直接删目录会把「只是没初始化」变成「数据没了」，所以不删、不 exit，报出缺什么
    # 就交给结尾的逐项核对（它会把这整条 <repo>/<path> 报未初始化，并带上真正的上游失败）。
    # `|| true` 是必需的：git config 查不到键时 exit 1，而 `set -e` 不覆盖赋值里的命令
    # 替换，脚本会带着空 url 继续，然后死在 `clone '': No such file or directory`。
    url="$(git -C "$repo" config -f .gitmodules --get "submodule.$path.url" || true)"
    if [ -z "$url" ]; then
        echo "$prefix WARN: no submodule.$path.url in $repo/.gitmodules; not touching $repo/$path." >&2
        echo "$prefix That file comes from $repo's own tree — if the directory is empty or on the" >&2
        echo "$prefix wrong commit, the superproject's checkout failed earlier (see the git output above)." >&2
        return 0
    fi
    # 不拿 $repo 冒充 clone 源：它不是 git 仓库（只是个含子模块的目录），
    # `git clone --filter=blob:none '<repo>'` 只会当场失败，把注释承诺的 WARN 变成一次无归因退出。
    if [ -z "$src_url" ]; then
        echo "$prefix WARN: $repo/$path needs a rebuild but the caller passed no source URL;" >&2
        echo "$prefix tell the operator to re-run tools/init-submodules.sh (which rebuilds it), or pass one." >&2
        return 0
    fi

    # 先建到临时同级目录，成了才换名。残留的半个 checkout 会让 clone 直接报「目录非空」，
    # 而这个目录无论处于什么状态，唯一正确的姿势都是重建 —— 但重建不该把旁边的
    # <repo> 工作树赔进去。
    tmp="$repo/$path.tmp.$$"
    rm -rf "$tmp"
    _fetch_pin_cleanup() { rm -rf "$tmp"; }
    _fetch_pin_bail() {
        _fetch_pin_cleanup
        echo "$1" >&2
        echo "$2" >&2
        exit 1
    }
    git clone --quiet --no-checkout --filter=blob:none --single-branch \
        --branch "$branch" "$url" "$tmp" ||
        _fetch_pin_bail \
            "$prefix ERROR: could not clone $url (submodule.$path.url) at branch '$branch'." \
            "$prefix $repo/$path was left untouched; the URL or the network is the suspect, not the pin."
    # 分支尖端可能是 FETCH_HEAD 上的临时对象，先落成本地 ref 再校验可达性。
    git -C "$tmp" fetch --quiet origin "+refs/heads/$branch:refs/remotes/origin/$branch"
    if ! git -C "$tmp" cat-file -e "$want^{commit}" 2>/dev/null; then
        # 分支上取不到这个 pin，它可能在别的分支或 tag 上。按 SHA 再要一次：这步是
        # 可达性兜底，不是放宽 pin —— 要的仍是同一个 gitlink SHA。
        echo "$prefix $path: $want is not on '$branch'; falling back to a bare-SHA fetch" >&2
        if ! git -C "$tmp" fetch --quiet origin "$want"; then
            # 「pin 被清洗」和「url 根本不通」在这里长得一样，原因不一样，别把人往错的
            # 方向指：url 连不上时，抬 gitlink 或改 tag 都救不了。判据是远端是否答得出
            # 它的分支表 —— 那一步不走 pin，只验 url 本身。
            if ! git ls-remote --heads "$url" >/dev/null 2>&1; then
                _fetch_pin_bail \
                    "$prefix ERROR: cannot reach $url (submodule.$path.url); $path was not rebuilt." \
                    "$prefix The pin $want is not the suspect here: that URL does not answer at all. Fix the URL (or the network), then rerun; $repo/$path was left untouched."
            fi
            _fetch_pin_bail \
                "$prefix ERROR: pinned commit $want is not on $url (tried branch '$branch' and bare SHA)." \
                "$prefix This is the upstream-cleaned-commit case: bump the gitlink in $repo to a commit whose nested pin still exists, or update the tag in .gitmodules. $repo/$path was left untouched."
        fi
    fi
    git -C "$tmp" checkout --quiet --detach "$want" ||
        _fetch_pin_bail \
            "$prefix ERROR: could not check out $want in the fresh clone of $url." \
            "$prefix $repo/$path was left untouched."
    rm -rf "$repo/$path"
    mv "$tmp" "$repo/$path"
    echo "$prefix $path -> $want"
}

# check_submodules <prefix> [allow-fail-paths...]
#   逐项核对 `git submodule status --recursive`：未初始化（前置 `-`）、
#   工作树与 gitlink 不一致（前置 `+`）、历史不可达（前置 `U`）都点名报错。
#   用于兜住 `|| true` 罩住的 top-level 递归初始化——否则 lief 或 unicorn
#   拉不动时脚本照样打印 ok、退出 0，失败被推到几分钟后的 native 编译。
#   第一个参数是日志前缀，与 fetch_pin 的 <prefix> 同一个约定：由调用方给
#   （[submodules] / [rz-ghidra]），本文件不替调用方决定它叫什么。
#   其余参数是允许失败的前缀：某个路径本身或它的父路径命中即放行。
#
#   这是本脚本唯一的裁定点：前面的 fetch_pin 遇到「还没法判定」的状态只警告不退出，
#   由这里一次性点名所有真实失败，报错就不会指向别处。
#   必须直接调用（同 pin_of）：失败用 exit 1 表达，放进 $( ) 会被子 shell 吃掉。
check_submodules() {
    local prefix="${1:?check_submodules needs a log prefix}"
    shift
    local allow=("$@") bad=0 line flag path a
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        flag="${line:0:1}"
        path="$(printf '%s' "$line" | awk '{print $2}')"
        case "$flag" in
            - | + | U) ;;
            *) continue ;;
        esac
        for a in "${allow[@]}"; do
            case "$path" in
                "$a" | "$a"/*) continue 2 ;;
            esac
        done
        case "$flag" in
            -) echo "$prefix ERROR: submodule not initialised: $path" >&2 ;;
            +) echo "$prefix ERROR: submodule work tree is not at its gitlink: $path" >&2 ;;
            U) echo "$prefix ERROR: pinned commit of $path is not reachable (again: clone it and check .gitmodules)" >&2 ;;
        esac
        bad=$((bad + 1))
    done < <(git submodule status --recursive)

    if [ "$bad" -ne 0 ]; then
        echo "$prefix ERROR: $bad submodule(s) failed to initialise; see the lines above." >&2
        echo "$prefix Failing here on purpose: these pins are needed by the native build." >&2
        exit 1
    fi
}

# check_gitlinks <prefix> <repo> <path>...
#   逐条核对「<repo>/<path> 的 HEAD 是否就是 <repo> 自己 HEAD 里那个 gitlink 记的提交」，
#   不是就点名报错。父仓那层的 gitlink 由调用方先核（它才知道 <repo> 该在哪个提交上）。
#   第一个参数是日志前缀（同 fetch_pin / check_submodules 的约定）。
#
#   为什么单独要这一道：pin_of 是从 <repo> 的 HEAD 读 pin 的，所以「<repo> 停在错提交上」
#   这件事本身它看不出来 —— 它会老老实实把错树里的 pin 读出来、置备好、报成功。空壳能靠
#   heal_submodule_checkout 救回，但工作树是满的、只是停在别的提交上（本地构建的人的常见
#   状态）时没人救，而这种状态恰恰会编译出与校验不一致的树。
#   tools/init-submodules.sh 有 check_submodules 兜 status 的 `+`；build-rz-ghidra-android.sh
#   只调 fetch_pin，没有那一道，所以它自己必须补这一次核对。
#   必须直接调用（同 pin_of）：失败用 exit 1 表达，放进 $( ) 会被子 shell 吃掉。
check_gitlinks() {
    local prefix="${1:?check_gitlinks needs a log prefix}"
    local repo="${2:?check_gitlinks needs a submodule repo}"
    shift 2
    local path want got bad=0
    for path in "$@"; do
        want="$(git -C "$repo" ls-tree HEAD -- "$path" 2>/dev/null | awk '$1 == "160000" { print $3 }' || true)"
        got="$(git -C "$repo/$path" rev-parse HEAD 2>/dev/null || true)"
        if [ -z "$want" ]; then
            echo "$prefix ERROR: $repo's HEAD records no gitlink for $path" >&2
            bad=$((bad + 1))
        elif [ "$got" != "$want" ]; then
            echo "$prefix ERROR: $repo/$path is at ${got:-<nothing>}, but the superproject pins $want" >&2
            bad=$((bad + 1))
        fi
    done
    if [ "$bad" -ne 0 ]; then
        echo "$prefix ERROR: $bad nested checkout(s) do not match their gitlink; refusing to build the wrong tree." >&2
        echo "$prefix Run tools/init-submodules.sh from the repo root to put them back on the pin." >&2
        exit 1
    fi
}
