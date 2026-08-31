package de.eudiwallet.backend.shared.keyrollover

fun interface KeySource<out T> {
    fun current(): T
}

internal const val STUB = "stub"
