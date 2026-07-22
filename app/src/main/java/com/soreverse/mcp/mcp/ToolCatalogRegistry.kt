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

    fun leanNames(popularity: Map<String, Long>? = null, promotionSlots: Int = 5): List<String> {
        val base = handlers
            .filter { it.meta.cls == ToolClass.CORE || it.meta.cls == ToolClass.META || it.meta.category == "lowlevel" }
            .mapTo(linkedSetOf()) { it.meta.name }
        if (popularity.isNullOrEmpty() || promotionSlots <= 0) return base.toList()
        val promoted = handlers.withIndex()
            .filter { it.value.meta.cls == ToolClass.EXTRA && popularity.containsKey(it.value.meta.name) }
            .sortedWith(compareByDescending<IndexedValue<ToolHandler>> { popularity.getValue(it.value.meta.name) }.thenBy { it.index })
            .take(promotionSlots)
            .map { it.value.meta.name }
        base.addAll(promoted)
        return base.toList()
    }

    fun description(name: String, zh: Boolean): String =
        byName[name]?.let { if (zh) it.meta.zh else it.meta.en } ?: name

    fun categoryOf(name: String): String? = byName[name]?.meta?.category
}
