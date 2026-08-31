package de.eudiwallet.backend.statuslist

import de.eudiwallet.backend.shared.telemetry.runBlockingWithTelemetry
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.CoroutineDispatcher
import org.springframework.beans.factory.annotation.Value
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import java.time.Duration

@Component
class StatusListGc(
    private val statusListService: StatusListService,
    private val ioDispatcher: CoroutineDispatcher,
    @Value($$"${statuslist.gc.batch-size:5000}") private val batchSize: Int,
    @Value($$"${statuslist.gc.list-delete-slack:P1D}") private val listDeleteSlack: Duration,
) {
    private val log = KotlinLogging.logger {}

    init {
        require(batchSize > 0) { "statuslist.gc.batch-size must be positive" }
    }

    @Scheduled(
        scheduler = "statusListGcScheduler",
        fixedDelayString = $$"${statuslist.gc.interval:PT24H}",
        initialDelayString = $$"${statuslist.gc.initial-delay:PT1H}",
    )
    fun scheduledGc() = gcOnce()

    fun gcOnce() {
        deleteExpiredEntries()
        deleteDeadLists()
    }

    @Suppress("TooGenericExceptionCaught")
    private fun deleteExpiredEntries() {
        try {
            val removed = runBlockingWithTelemetry(ioDispatcher) { statusListService.gcExpiredEntries(batchSize) }
            if (removed > 0) log.info { "Status-list GC removed $removed expired entries" }
        } catch (e: Exception) {
            log.error(e) { "Status-list entry GC failed; retrying on the next scheduled run" }
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private fun deleteDeadLists() {
        try {
            val deleted = runBlockingWithTelemetry(ioDispatcher) { statusListService.gcExhaustedLists(listDeleteSlack) }
            if (deleted > 0) log.info { "Status-list GC deleted $deleted exhausted lists" }
        } catch (e: Exception) {
            log.error(e) { "Status-list list GC failed; retrying on the next scheduled run" }
        }
    }
}
