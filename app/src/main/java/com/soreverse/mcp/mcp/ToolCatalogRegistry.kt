package com.soreverse.mcp.mcp

class ToolCatalogRegistry(handlers: List<ToolHandler>) {
    val handlers: List<ToolHandler> = handlers.toList()
    val byName: Map<String, ToolHandler>
    val names: List<String>
    val heavyNames: Set<String>

    init {
        names = this.handlers.map { it.meta.name }
        require(names.distinct().size == names.size) { "Tool names must be unique" }
        byName = this.handlers.associateBy { it.meta.name }
        heavyNames = this.handlers.filter { it.meta.heavy }.mapTo(linkedSetOf()) { it.meta.name }
    }

    /**
     * Categories whose tools are dispatch gateways rather than direct evidence
     * calls: they fan out to a whole engine or a whole sub-agent, so the client
     * needs the name to reach the capability at all. Hiding them behind EXTRA
     * promotion would mean a gateway nobody has called yet is unreachable —
     * `agent_api` (the sub-agent door) was exactly that, since lean mode is on by
     * default and promotion requires prior popularity.
     */
    private fun ToolMeta.isGateway(): Boolean = category in GATEWAY_CATEGORIES

    fun leanNames(popularity: Map<String, Long>? = null, promotionSlots: Int = 5): List<String> {
        val base = handlers
            .filter {
                it.meta.cls == ToolClass.CORE ||
                    it.meta.cls == ToolClass.META ||
                    it.meta.isGateway()
            }
            .mapTo(linkedSetOf()) { it.meta.name }
        if (popularity.isNullOrEmpty() || promotionSlots <= 0) return base.toList()
        val promoted = handlers.withIndex()
            .filter {
                it.value.meta.cls == ToolClass.EXTRA &&
                    !it.value.meta.isGateway() &&
                    popularity.containsKey(it.value.meta.name)
            }
            .sortedWith(
                compareByDescending<IndexedValue<ToolHandler>> {
                    popularity.getValue(it.value.meta.name)
                }.thenBy { it.index }
            )
            .take(promotionSlots)
            .map { it.value.meta.name }
        base.addAll(promoted)
        return base.toList()
    }

    fun description(name: String, zh: Boolean): String = byName[name]?.let { if (zh) it.meta.zh else it.meta.en } ?: name

    fun categoryOf(name: String): String? = byName[name]?.meta?.category

    private companion object {
        val GATEWAY_CATEGORIES = setOf("lowlevel", "agent")
    }
}
