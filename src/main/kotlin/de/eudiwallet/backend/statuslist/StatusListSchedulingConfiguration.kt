package de.eudiwallet.backend.statuslist

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler

@Configuration
@EnableScheduling
class StatusListSchedulingConfiguration {
    @Bean("statusListGcScheduler")
    fun statusListGcScheduler(): ThreadPoolTaskScheduler =
        ThreadPoolTaskScheduler().apply {
            poolSize = 1
            setThreadNamePrefix("statuslist-gc-")
            isDaemon = true
        }
}
