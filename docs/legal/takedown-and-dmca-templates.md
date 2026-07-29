# 平台投诉与 DMCA 模板 / Takedown & DMCA templates

> 配合 `gpl-infringement-notice.md` 使用。先做证据固定（见文末清单），再按平台选择对应模板提交。

---

## 一、论坛投诉模板（binmt / 吾爱系等中文论坛）

**标题：** 侵权投诉：帖子《`<帖子标题>`》违反 GPL-3.0 开源协议、侵犯软件著作权

**正文：**

管理员您好，我是开源软件 **SOMCP**（https://github.com/bilieebiliee1-design/SOMCP ，GPL-3.0-only）的著作权人。

现举报本站帖子：`<帖子链接>`，发布者：`<ID>`。

该帖发布的「`<侵权作品名>`」系基于我的 SOMCP 二次开发的衍生作品（核心功能、专有工具命名 `apk_analyze`/`edit_asm`/`build_so`/`flutter_blutter` 等、技术架构高度一致），但在分发时：未提供完整对应源代码、删除了原作者署名、未以 GPL-3.0 继续授权、并以"原创"名义发布。此举违反 GPL-3.0 第 4、5 条，依第 8 条其授权已自动终止，构成著作权侵权。

依据《中华人民共和国著作权法》《计算机软件保护条例》及贵站社区规则，请求贵站：

1. 下架 / 删除该侵权帖子及其下载链接；
2. 对发布者作出相应处理；
3. 如需，我可提供：我的仓库提交历史、Release 记录、两者功能与工具命名比对、以及运行时溯源证据（该软件运行时会输出源自 SOMCP 的许可证与仓库信息）。

我的联系方式：`<联系方式>`。感谢处理。

---

## 二、网盘 / 云存储投诉模板（小飞机网盘、蓝奏云等）

**收件：** `<网盘投诉邮箱 / 举报入口>`

我是 SOMCP（https://github.com/bilieebiliee1-design/SOMCP ，GPL-3.0-only）著作权人。贵平台下述分享链接承载的文件侵犯我的软件著作权并违反 GPL-3.0：

- 分享链接：`<链接>`
- 文件名：`<文件名>`
- 侵权说明：该文件为我的开源软件的二改闭源分发版，未提供源代码、删除署名、未沿用 GPL-3.0。

依据《信息网络传播权保护条例》，请贵平台及时删除 / 断开该文件的访问链接。我确认：本通知内容真实，我为该作品权利人，如有不实我愿承担相应法律责任。

权利人：`<署名>`　联系方式：`<联系方式>`　日期：`<日期>`

---

## 三、GitHub DMCA 模板（若二改被上传到 GitHub/Gitee）

> 提交入口：https://github.com/contact/dmca 。GitHub 要求本人签名与真实联系方式。

```
I am the copyright owner of SOMCP (https://github.com/bilieebiliee1-design/SOMCP),
licensed under GPL-3.0-only.

The repository/file at <infringing URL> is a derivative of my work,
redistributed without the complete corresponding source code, with my
copyright/attribution removed, and not licensed under GPL-3.0 — in breach of
GPL-3.0 sections 4–5, terminating the license under section 8.

Original work: https://github.com/bilieebiliee1-design/SOMCP
Infringing material: <URL(s)>

I have a good faith belief that the use of the material is not authorized by the
copyright owner, its agent, or the law. The information in this notice is
accurate, and under penalty of perjury, I am the copyright owner or authorized
to act on the owner's behalf.

Signed: <full legal name>
Contact: <address / phone / email>
Date: <YYYY-MM-DD>
```

---

## 四、证据固定清单（务必先做，再投诉）

1. **网页取证**：对侵权帖子 / 分享页做「带可信时间戳的整页截图 + 录屏」（可用权利卫士、联合信任时间戳，或直接公证）。
2. **下载留存**：下载侵权成品（APK / 安装包），记录链接、发布者、发布时间、文件哈希（SHA-256）。
3. **同一性证据**：
   - 包名 `com.soreverse.mcp`；
   - 发布签名指纹（见 `app/build.gradle.kts` 的 `EXPECTED_SIGNER_SHA256`）；
   - 运行时溯源输出（MCP `initialize`/健康检查返回、关于页显示的许可证与上游仓库）；
   - 独有工具命名、`librz_native.so` 等原生库、UI 文案与字符串比对；
   - 反编译比对 smali / 资源 / 字符串。
4. **权属证据**：GitHub 仓库创建时间、完整提交历史、各版本 Release、（可选）软件著作权登记证书。
5. **沟通记录**：告知函的发送与对方已读/回复记录。

> 建议顺序：固定证据 → 发合规告知函（给期限）→ 逾期则平台下架 + DMCA + 社区通报 → 视损失决定是否诉讼。
