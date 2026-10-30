#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""把 CNB 仓库 main 的提交历史重写为 GitHub 可验证（Verified）签名后推送。

背景：CNB → GitHub 的同步流水线直接推送 CNB 的提交对象。这些提交的
committer 是 CNB 侧的合并身份（如 cnb <cnb@cnb.local>），签名用的是 CNB
的密钥。GitHub 既不认识这个邮箱、也不认识这把密钥，于是同步过去的提交
一律显示 Unverified。

做法：把 main 的每个提交用同样的 tree / 父提交 / 作者信息 / 提交信息重新
提交一次，committer 换成 GitHub 账号身份，签名用已注册到该 GitHub 账号的
GPG 密钥，标签按新提交重新创建并签名，最后强推回 GitHub。

GitHub 侧是 CNB 的镜像仓库（同步一直 force 覆盖），所以重写 SHA 不影响
CNB 这边的真实历史。

依赖：git、gnupg。
环境变量：
    TARGET_URL            目标仓库 URL（必填）
    SOURCE_REF            源 ref，默认 refs/remotes/origin/main
    GIT_USERNAME/GIT_ACCESS_TOKEN   推送凭据（可选，脚本内已配好 remote 时不需要）
    GIT_COMMITTER_NAME/GIT_COMMITTER_EMAIL   重写后的提交者身份（必填）
    GIT_AUTHOR_NAME/GIT_AUTHOR_EMAIL         缺省时的作者身份
    GPG_PRIVATE_KEY_B64   GPG 私钥（base64，必填）
    GPG_SIGNING_KEY_ID    签名密钥指纹（可选，自动取）
"""

import base64
import os
import subprocess
import sys


def run(args, env=None, stdin=None, check=True):
    proc = subprocess.run(args, env=env, input=stdin, capture_output=True)
    if check and proc.returncode != 0:
        sys.stderr.write(proc.stdout.decode("utf-8", "replace"))
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit("command failed: %s" % " ".join(args))
    return proc.stdout.decode("utf-8", "replace")


def git(*args, **kwargs):
    return run(["git"] + list(args), **kwargs)


def import_key():
    b64 = os.environ.get("GPG_PRIVATE_KEY_B64", "").strip()
    if not b64:
        raise SystemExit("缺少 GPG_PRIVATE_KEY_B64")
    key_path = "/tmp/signing_key.asc"
    with open(key_path, "wb") as fh:
        fh.write(base64.b64decode(b64))
    run(["gpg", "--batch", "--import", key_path])
    key_id = os.environ.get("GPG_SIGNING_KEY_ID", "").strip()
    if not key_id:
        for line in git("--list-secret-keys", "--keyid-format=long").splitlines():
            if line.startswith("sec"):
                key_id = line.split("/")[-1].split()[0]
                break
    git("config", "user.signingkey", key_id)
    git("config", "gpg.format", "openpgp")
    return key_id


def parse_ident(raw):
    """'Name <mail> 1234567890 +0800' -> (name, mail, '1234567890 +0800')"""
    raw = raw.strip()
    name, _, rest = raw.partition(" <")
    mail = rest.split(">", 1)[0] if ">" in rest else ""
    tail = rest.split(">", 1)[1].strip() if ">" in rest else ""
    date = tail
    return name.strip(), mail.strip(), date.strip()


def commit_meta(sha):
    raw = git("cat-file", "commit", sha)
    head, _, message = raw.partition("\n\n")
    meta = {"message": message, "encoding": ""}
    for line in head.split("\n"):
        if line.startswith("gpgsig "):
            continue
        key, _, value = line.partition(" ")
        if key in ("author", "committer"):
            name, mail, date = parse_ident(value)
            meta[key + "_name"] = name
            meta[key + "_email"] = mail
            meta[key + "_date"] = date
        else:
            meta[key] = value
    return meta


def rewrite_commits(source_ref, committer_name, committer_email, fallback_author):
    order = git("rev-list", "--reverse", "--topo-order", source_ref).split()
    mapping = {}
    for sha in order:
        meta = commit_meta(sha)
        tree = git("rev-parse", "%s^{tree}" % sha).strip()
        parents = git("rev-list", "--parents", "-n", "1", sha).split()[1:]
        new_parents = [mapping[p] for p in parents if p in mapping]
        env = dict(os.environ)
        env["GIT_AUTHOR_NAME"] = meta.get("author_name") or fallback_author[0]
        env["GIT_AUTHOR_EMAIL"] = meta.get("author_email") or fallback_author[1]
        env["GIT_AUTHOR_DATE"] = meta.get("author_date", "")
        env["GIT_COMMITTER_NAME"] = committer_name
        env["GIT_COMMITTER_EMAIL"] = committer_email
        env["GIT_COMMITTER_DATE"] = meta.get("committer_date", "")
        args = ["git", "commit-tree", tree]
        for parent in new_parents:
            args += ["-p", parent]
        args.append("-S")
        new_sha = run(args, env=env, stdin=meta["message"].encode("utf-8")).strip()
        mapping[sha] = new_sha
    return mapping


def rewrite_tags(mapping, committer_name, committer_email):
    names = []
    lines = git("for-each-ref", "--format=%(refname:short) %(objecttype) %(objectname)",
                "refs/tags").splitlines()
    for line in lines:
        if not line.strip():
            continue
        name, objtype, objname = line.split()
        if objtype == "tag":
            raw = git("cat-file", "tag", objname)
            head, _, message = raw.partition("\n\n")
            target = None
            tagger = None
            for ln in head.split("\n"):
                if ln.startswith("object "):
                    target = ln.split(" ", 1)[1]
                elif ln.startswith("tagger "):
                    tagger = ln.split(" ", 1)[1]
            if target not in mapping:
                continue
            tname, tmail, tdate = parse_ident(tagger or "%s <%s> 0 +0000" % (committer_name, committer_email))
            body = "object %s\ntype commit\ntag %s\ntagger %s <%s> %s\n\n%s" % (
                mapping[target], name, tname, tmail, tdate or "0 +0000", message)
            new_sha = run(["git", "mktag"], stdin=body.encode("utf-8")).strip()
            git("tag", "-f", name, new_sha)
        else:
            if objname not in mapping:
                continue
            git("tag", "-f", name, mapping[objname])
        names.append(name)
    return names


def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description="重写并重签名 CNB 历史后推送到 GitHub")
    parser.add_argument("--source-ref", default=os.environ.get("SOURCE_REF", "HEAD"))
    parser.add_argument("--target-url", default=os.environ.get("TARGET_URL", ""))
    return parser.parse_args()


def resolve_source(source_ref):
    """把用户给的 ref 归一成 'refs/remotes/origin/main' 或本地 ref。"""
    ref = source_ref.strip()
    if ref in ("HEAD", "main", "master"):
        return "HEAD"
    return ref


def target_url_with_auth(url):
    """若给了 GIT_USERNAME / GIT_ACCESS_TOKEN，就把凭据嵌进 URL。"""
    user = os.environ.get("GIT_USERNAME", "").strip()
    token = os.environ.get("GIT_ACCESS_TOKEN", "").strip()
    if not user or not token:
        return url
    if "@" in url.split("/", 3)[2]:
        return url
    scheme, _, rest = url.partition("://")
    return "%s://%s:%s@%s" % (scheme, user, token, rest)


def main():
    args = parse_args()
    target_url = target_url_with_auth(args.target_url)
    if not target_url:
        raise SystemExit("缺少 TARGET_URL")
    source_ref = resolve_source(args.source_ref)
    committer_name = os.environ.get("GIT_COMMITTER_NAME", "").strip()
    committer_email = os.environ.get("GIT_COMMITTER_EMAIL", "").strip()
    author = (os.environ.get("GIT_AUTHOR_NAME", "").strip() or committer_name,
              os.environ.get("GIT_AUTHOR_EMAIL", "").strip() or committer_email)
    if not committer_name or not committer_email:
        raise SystemExit("缺少 GIT_COMMITTER_NAME / GIT_COMMITTER_EMAIL")
    key_id = import_key()
    mapping = rewrite_commits(source_ref, committer_name, committer_email, author)
    tags = rewrite_tags(mapping, committer_name, committer_email)
    tip = mapping[git("rev-parse", source_ref).strip()]
    git("push", "--force", target_url, "%s:refs/heads/main" % tip)
    if tags:
        git("push", "--force", target_url, "--tags")
    print("rewritten %d commits, %d tags, signing key %s" % (len(mapping), len(tags), key_id))


if __name__ == "__main__":
    main()
