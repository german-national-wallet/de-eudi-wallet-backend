package de.eudiwallet.backend.shared.keyrollover

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler

@Configuration
@EnableScheduling
class KeyRolloverConfiguration {
    @Bean("keyRolloverScheduler")
    fun keyRolloverScheduler(): ThreadPoolTaskScheduler =
        ThreadPoolTaskScheduler().apply {
            poolSize = 1
            setThreadNamePrefix("key-rollover-")
            isDaemon = true
        }
}
