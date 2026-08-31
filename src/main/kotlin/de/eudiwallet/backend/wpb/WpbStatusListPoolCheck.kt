package de.eudiwallet.backend.wpb

import de.eudiwallet.backend.statuslist.StatusListConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Component

@Component
@ConditionalOnProperty(prefix = "wpb", name = ["enabled"], havingValue = "true")
class WpbStatusListPoolCheck(
    config: StatusListConfiguration,
) {
    init {
        requireNotNull(config.poolById(WPB_WIA_POOL)) {
            "wpb requires status-list pool '$WPB_WIA_POOL' to be configured (statuslist.pools.$WPB_WIA_POOL)"
        }
    }
}
