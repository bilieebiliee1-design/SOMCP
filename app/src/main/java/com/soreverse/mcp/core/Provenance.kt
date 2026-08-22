/*
 * SOMCP - Android native SO reverse-engineering MCP server
 * Copyright (C) 2026 SOMCP authors <https://github.com/bilieebiliee1-design/SOMCP>
 *
 * This file is part of SOMCP and is licensed under the GNU Affero General Public
 * License v3.0 only (AGPL-3.0-only). Any redistribution, including modified or
 * rebranded builds, MUST keep this notice, remain licensed under AGPL-3.0, and
 * make the complete corresponding source code available. See the LICENSE file.
 */
package com.soreverse.mcp.core

import com.soreverse.mcp.BuildConfig
import org.json.JSONObject

/**
 * Single source of truth for authorship, license and upstream-origin metadata.
 *
 * These values are surfaced at runtime (MCP `initialize`, `meta_info` health,
 * the About screen) so that any redistributed or rebranded build carries a
 * verifiable, hard-to-strip pointer back to the original AGPL-3.0 project.
 * Removing this provenance requires editing source, and doing so while
 * continuing to distribute a closed-source build is itself an AGPL-3.0 breach.
 */
object Provenance {
    const val PROJECT = "SOMCP"
    const val LICENSE = "AGPL-3.0-only"
    const val UPSTREAM = "https://github.com/bilieebiliee1-design/SOMCP"
    const val COPYRIGHT = "Copyright (C) 2026 SOMCP authors"
    const val PACKAGE = "com.soreverse.mcp"
    const val REDISTRIBUTION_NOTICE =
        "SOMCP is free software under AGPL-3.0-only, protected by copyright law " +
            "(in the PRC: the Copyright Law and the Regulations on the Protection " +
            "of Computer Software). ANY redistribution — including modified, " +
            "rebranded or repackaged builds — MUST retain this copyright and " +
            "license notice, remain licensed under AGPL-3.0, and provide the " +
            "complete corresponding source code to every recipient. Closed-source " +
            "distribution, stripping attribution, or passing this work off as " +
            "original is infringement: the GPL is an enforceable license agreement " +
            "upheld by courts (e.g. the PRC cases DigiTalent v. UCweb and Luohe v. " +
            "Fengling), and rights holders may demand takedown, cessation, public " +
            "correction and damages."

    /** Provenance block embedded into MCP/health JSON payloads. */
    fun json(): JSONObject = JSONObject()
        .put("project", PROJECT)
        .put("license", LICENSE)
        .put("upstream", UPSTREAM)
        .put("copyright", COPYRIGHT)
        .put("applicationId", PACKAGE)
        .put("version", BuildConfig.VERSION_NAME)
        .put("notice", REDISTRIBUTION_NOTICE)
}
