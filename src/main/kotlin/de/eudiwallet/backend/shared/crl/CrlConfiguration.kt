package de.eudiwallet.backend.shared.crl

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler

@Configuration
@EnableScheduling
class CrlConfiguration {
    @Bean("crlRefreshScheduler")
    fun crlRefreshScheduler(): ThreadPoolTaskScheduler =
        ThreadPoolTaskScheduler().apply {
            poolSize = 1
            setThreadNamePrefix("crl-refresh-")
            isDaemon = true
        }
}
