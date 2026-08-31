package de.eudiwallet.backend.rwsca

import de.eudiwallet.backend.shared.hsm.BuildDocsHsmProvider
import de.eudiwallet.backend.shared.hsm.HsmConfiguration
import de.eudiwallet.backend.shared.hsm.HsmHealthIndicatorBase
import de.eudiwallet.backend.shared.hsm.HsmModule
import de.eudiwallet.backend.shared.hsm.HsmProvider
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component

const val RWSCA_WI_HSM_PROVIDER = "rwscaWiHsmProvider"

@Configuration
class RwscaWiHsmConfiguration {
    @Bean(RWSCA_WI_HSM_PROVIDER)
    @Profile("!build-docs")
    fun rwscaWiHsmProvider(
        rwscaConfiguration: RwscaConfiguration,
        hsmModule: HsmModule,
    ): HsmProvider = hsmModule.provider(rwscaConfiguration.wiSlot)

    @Bean(RWSCA_WI_HSM_PROVIDER)
    @Profile("build-docs")
    fun docsRwscaWiHsmProvider(): HsmProvider = BuildDocsHsmProvider()
}

@Component
class RwscaWiHsmHealthIndicator(
    @Qualifier(RWSCA_WI_HSM_PROVIDER)
    hsmProvider: HsmProvider,
    config: HsmConfiguration,
    rwscaConfiguration: RwscaConfiguration,
) : HsmHealthIndicatorBase(hsmProvider, config.moduleLibrary, rwscaConfiguration.wiSlot.label)
