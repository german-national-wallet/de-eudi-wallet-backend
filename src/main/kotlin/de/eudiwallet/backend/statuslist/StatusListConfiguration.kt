package de.eudiwallet.backend.statuslist

import de.eudiwallet.backend.shared.crypto.readX509Cert
import de.eudiwallet.backend.shared.hsm.HsmConfiguration
import de.eudiwallet.backend.shared.hsm.HsmProvider
import de.eudiwallet.backend.shared.keyrollover.AsymmetricSigningLineage
import de.eudiwallet.backend.shared.keyrollover.CertifiedKey
import de.eudiwallet.backend.shared.keyrollover.KeySource
import de.eudiwallet.backend.shared.keyrollover.stubCertifiedKeySource
import de.eudiwallet.backend.shared.s3.S3CertChainProvider
import de.eudiwallet.backend.shared.telemetry.MetricsService
import kotlinx.coroutines.CoroutineDispatcher
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import org.springframework.core.io.Resource
import java.security.cert.X509Certificate
import java.time.Duration
import java.util.UUID

@ConfigurationProperties(prefix = "statuslist")
class StatusListConfiguration(
    publicUrl: String,
    val pathSegment: String,
    pools: Map<String, PoolProperties>,
) {
    private val baseUrl = publicUrl.trimEnd('/')

    private val resolvedPools: Map<String, Pool> =
        pools.mapValues { (id, props) -> props.resolve(id) }.also { it.values.forEach(Pool::validate) }

    init {
        require(pathSegment.isNotBlank()) { "statuslist.path-segment must not be blank" }
    }

    fun pool(id: String): Pool = requireNotNull(resolvedPools[id]) { "no status-list pool configured for '$id'" }

    fun pools(): Collection<Pool> = resolvedPools.values

    fun poolById(id: String): Pool? = resolvedPools[id]

    fun listUri(
        pool: Pool,
        listId: UUID,
    ): String = "$baseUrl/status-lists/$pathSegment/${pool.id}/$listId"

    fun aggregationUri(pool: Pool): String = "$baseUrl/status-lists/$pathSegment/${pool.id}/aggregation"
}

class PoolProperties(
    val entriesPerList: Int,
    val bitsPerEntry: Int,
    val issuer: String,
    val ttl: Duration,
    val lifetime: Duration,
    val tslAuthKeyPrefix: String,
    val tslRootCertPath: Resource,
) {
    fun resolve(id: String): Pool =
        Pool(
            id = id,
            entriesPerList = entriesPerList,
            bitsPerEntry = bitsPerEntry,
            issuer = issuer,
            ttl = ttl,
            lifetime = lifetime,
            tslAuthKeyPrefix = tslAuthKeyPrefix,
            tslRootCert = readX509Cert(tslRootCertPath).apply { checkValidity() },
        )
}

data class Pool(
    val id: String,
    val entriesPerList: Int,
    val bitsPerEntry: Int,
    val issuer: String,
    val ttl: Duration,
    val lifetime: Duration,
    val tslAuthKeyPrefix: String,
    val tslRootCert: X509Certificate,
) {
    fun validate() {
        require(entriesPerList >= MIN_SIZE) {
            "pool '$id': entriesPerList must be at least $MIN_SIZE (smaller pools make index scattering too slow)"
        }
        require(bitsPerEntry in StatusListCodec.ALLOWED_BITS) {
            "pool '$id': bitsPerEntry must be one of ${StatusListCodec.ALLOWED_BITS}"
        }
        require((entriesPerList.toLong() * bitsPerEntry) % Byte.SIZE_BITS == 0L) {
            "pool '$id': entriesPerList*bitsPerEntry must be a whole number of bytes"
        }
        require(!ttl.isZero && !ttl.isNegative) { "pool '$id': ttl must be positive" }
        require(lifetime >= ttl.multipliedBy(2)) { "pool '$id': lifetime must be at least 2*ttl" }
    }

    private companion object {
        const val MAX_SCATTER_TRIES = 128
        const val MIN_SIZE = FeistelPermutation.MIN_DOMAIN / MAX_SCATTER_TRIES
    }
}

@Configuration
class StatusListKeyProvider(
    private val config: StatusListConfiguration,
    private val hsmConfiguration: HsmConfiguration,
    private val hsmProvider: HsmProvider,
    private val s3CertChainProvider: S3CertChainProvider,
    private val ioDispatcher: CoroutineDispatcher,
    private val beanFactory: ConfigurableListableBeanFactory,
    private val metricsService: MetricsService,
) {
    @Bean
    @Profile("!build-docs")
    fun statusListSigningLineages(): Map<Pool, KeySource<CertifiedKey>> =
        config.pools().associateWith { pool ->
            AsymmetricSigningLineage(
                name = "statuslist-${pool.id}-auth",
                keyPrefix = pool.tslAuthKeyPrefix,
                slotLabel = hsmConfiguration.slotLabel,
                trustAnchor = pool.tslRootCert,
                hsmProvider = hsmProvider,
                s3CertChainProvider = s3CertChainProvider,
                ioDispatcher = ioDispatcher,
                metricsService = metricsService,
            ).also {
                it.initialize()
                beanFactory.registerSingleton("statusListSigner-${pool.id}", it)
            }
        }

    @Bean
    @Profile("build-docs")
    fun docsStatusListSigningLineages(): Map<Pool, KeySource<CertifiedKey>> =
        config.pools().associateWith { stubCertifiedKeySource() }
}
