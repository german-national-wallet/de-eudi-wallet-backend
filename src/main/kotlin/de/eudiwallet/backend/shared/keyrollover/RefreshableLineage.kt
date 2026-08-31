package de.eudiwallet.backend.shared.keyrollover

interface RefreshableLineage {
    val name: String

    fun refresh()
}
