package de.eudiwallet.backend.shared.keyrollover

import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.beans.factory.ObjectProvider
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import java.util.concurrent.locks.ReentrantLock

@Component
class KeyRolloverDriver(
    private val lineagesProvider: ObjectProvider<RefreshableLineage>,
) {
    private val log = KotlinLogging.logger {}
    private val lock = ReentrantLock()

    @Scheduled(
        scheduler = "keyRolloverScheduler",
        fixedDelayString = $$"${key-rollover.poll-interval:PT1H}",
        initialDelayString = $$"${key-rollover.initial-delay:PT1H}",
    )
    fun scheduledPoll() = pollOnce()

    fun pollOnce() {
        val lineages = lineagesProvider.toList()
        if (!lock.tryLock()) {
            log.debug { "Key rollover poll already in progress; skipping this tick" }
            return
        }
        try {
            lineages.forEach(::refreshLineage)
        } finally {
            lock.unlock()
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private fun refreshLineage(lineage: RefreshableLineage) {
        try {
            lineage.refresh()
        } catch (e: Exception) {
            log.error(e) { "Key rollover poll failed for lineage ${lineage.name}; holding its last-good material" }
        }
    }
}
