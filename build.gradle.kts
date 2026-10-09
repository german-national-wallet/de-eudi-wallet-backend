import org.springframework.boot.gradle.tasks.bundling.BootJar
import java.net.ServerSocket
import java.time.Duration

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.spring)
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
    alias(libs.plugins.ktlint)
    alias(libs.plugins.detekt)
    alias(libs.plugins.kover)
    alias(libs.plugins.sonarcube)
    alias(libs.plugins.springdoc)
    alias(libs.plugins.gatling)
    alias(libs.plugins.shadow)
    alias(libs.plugins.serialization)
    alias(libs.plugins.cyclonedx)
}

group = "de.eudiwallet"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(libs.versions.java.get()))
    }
}

repositories {
    mavenCentral()
}

extra["kotlin-coroutines.version"] = "1.11.0"

dependencyManagement {
    imports {
        mavenBom(libs.opentelemetry.instrumentation.bom.get().run { "$module:$version" })
    }
}

dependencies {
    implementation(libs.spring.boot.starter.webflux)
    implementation(libs.spring.boot.starter.webclient)
    implementation(libs.spring.boot.starter.security)
    implementation(libs.spring.boot.starter.actuator)
    implementation(libs.spring.boot.starter.validation)

    implementation(libs.spring.boot.starter.data.r2dbc)
    implementation(libs.spring.boot.starter.flyway)
    implementation(libs.postgresql)
    implementation(libs.r2dbc.postgresql)
    implementation(libs.flyway.postgresql)

    implementation(libs.spring.boot.kafka)

    implementation(libs.google.auth.library.oauth2.http)

    implementation(libs.kotlin.reflect)
    implementation(libs.kotlin.logging)
    implementation(libs.kotlinx.coroutines.reactor)

    implementation(platform(libs.jackson.bom))
    implementation(libs.jackson.module.kotlin)
    implementation(libs.kotlinx.serialization.json)

    implementation(libs.nimbus.jose.jwt)
    implementation(libs.bouncycastle.pkix.jdk18)
    implementation(libs.ngengine.bech32)
    implementation(libs.authlete.http.message.signatures)

    implementation(libs.springdoc.openapi.starter.webflux.ui)

    implementation(libs.logstash.logback.encoder)
    implementation(libs.opentelemetry.spring.boot.starter)
    implementation(libs.opentelemetry.extension.kotlin)
    implementation(libs.opentelemetry.samplers)

    implementation(libs.warden.makoto)

    implementation(libs.aws.smithy.signing)

    implementation(libs.vdurmont.semver4j)

    testImplementation(libs.spring.boot.starter.test)
    testImplementation(libs.spring.boot.starter.webflux.test)
    testImplementation(libs.spring.boot.data.r2dbc.test)
    testImplementation(libs.kotlin.test.junit5)
    testImplementation(libs.testcontainers.postgresql)
    testImplementation(libs.testcontainers)
    testImplementation(libs.testcontainers.kafka)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.kotest.runner.junit5)
    testImplementation(libs.kotest.framework.engine)
    testImplementation(libs.kotest.extensions.spring)
    testImplementation(libs.kotest.assertions.core)
    testImplementation(libs.mockk)
    testImplementation(libs.springmockk)
    testImplementation(libs.projectreactor.reactor.test)
    testImplementation(libs.openapitools.openapidiff.core) {
        exclude(group = "io.swagger.parser.v3", module = "swagger-parser-v3")
        exclude(group = "io.swagger.core.v3", module = "swagger-models")
    }
    testImplementation(libs.archunit.junit5)
    testImplementation(libs.jackson.dataformat.cbor)
    testImplementation(libs.okhttp.mockwebserver)

    gatlingImplementation(libs.spring.boot.starter.webflux)
    gatlingImplementation(libs.nimbus.jose.jwt)
    gatlingImplementation(libs.bouncycastle.pkix.jdk18)
    gatlingImplementation(libs.authlete.http.message.signatures)
    gatlingImplementation(libs.kotlinx.serialization.json)
    gatlingImplementation(libs.jackson.module.kotlin)
}

kotlin {
    compilerOptions {
        freeCompilerArgs.addAll("-Xjsr305=strict")
    }
}

shadow {
    addShadowJarToAssembleLifecycle = false
}

tasks.withType<Test> {
    timeout.set(Duration.ofMinutes(20))
    useJUnitPlatform()
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    maxHeapSize = "2g"
    System.getProperties().stringPropertyNames()
        .filter { it.startsWith("kotest.") }
        .forEach { systemProperty(it, System.getProperty(it)) }
    systemProperty("releaseVersion", providers.gradleProperty("releaseVersion").getOrElse(""))
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showExceptions = true
        showCauses = true
        showStackTraces = true
    }
    addTestListener(
        object : TestListener {
            override fun beforeSuite(suite: TestDescriptor) = Unit

            override fun beforeTest(testDescriptor: TestDescriptor) = Unit

            override fun afterTest(
                testDescriptor: TestDescriptor,
                result: TestResult,
            ) = Unit

            override fun afterSuite(
                suite: TestDescriptor,
                result: TestResult,
            ) {
                if (suite.parent == null) {
                    logger.lifecycle(
                        "Test results: ${result.testCount} tests, ${result.successfulTestCount} passed, " +
                            "${result.failedTestCount} failed, ${result.skippedTestCount} skipped",
                    )
                }
            }
        },
    )
}

tasks.register<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("gatlingJar") {
    group = "build"
    description = "Builds a runnable fat jar containing Gatling simulations and their runtime classpath."
    archiveBaseName.set("wallet-backend-gatling")
    archiveClassifier.set("")

    manifest {
        attributes("Main-Class" to "io.gatling.app.Gatling")
    }

    from(sourceSets["gatling"].output)
    configurations = listOf(project.configurations["gatlingRuntimeClasspath"])

    mergeServiceFiles()
    append("reference.conf")

    exclude(
        "META-INF/*.SF",
        "META-INF/*.DSA",
        "META-INF/*.RSA",
        "module-info.class",
    )
}

tasks.withType<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar> {
    isZip64 = true
}

val releaseVersion = providers.gradleProperty("releaseVersion")

springBoot {
    mainClass.set("de.eudiwallet.backend.WalletBackendApplicationKt")

    buildInfo {
        excludes.add("time")

        if (releaseVersion.isPresent) {
            properties {
                version.set(releaseVersion)
            }
        } else {
            excludes.add("version")
        }
    }
}

fun registerServiceBootJar(service: String) =
    tasks.register<BootJar>("bootJar$service") {
        group = "build"
        description = "Builds a runnable jar containing the $service service API."

        targetJavaVersion.set(JavaVersion.toVersion(libs.versions.java.get()))
        archiveClassifier.set(service.lowercase())
        this.mainClass.set("de.eudiwallet.backend.${service}ApplicationKt")

        classpath(sourceSets["main"].runtimeClasspath)
    }

registerServiceBootJar("Mdvm")
registerServiceBootJar("Rwsca")
registerServiceBootJar("Wpb")
registerServiceBootJar("Pns")

openApi {
    val customPort = ServerSocket(0).use { it.localPort }

    customBootRun.args = listOf("--spring.profiles.include=build-docs", "--server.port=$customPort")
    groupedApiMappings =
        mutableMapOf(
            "http://localhost:$customPort/v3/api-docs" to "all-api.json",
            "http://localhost:$customPort/v3/api-docs/rwsca" to "rwsca.json",
            "http://localhost:$customPort/v3/api-docs/mdvm" to "mdvm.json",
            "http://localhost:$customPort/v3/api-docs/wpb" to "wpb.json",
            "http://localhost:$customPort/v3/api-docs/pns" to "pns.json",
        )
}

detekt {
    buildUponDefaultConfig = true
    config.from("$projectDir/detekt.yml")
    source.setFrom("src/main/kotlin", "src/test/kotlin", "src/gatling/kotlin")
    ignoreFailures = false
}

ktlint {
    version.set(libs.versions.ktlint)
}

tasks.withType<org.springframework.boot.gradle.tasks.run.BootRun> {
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}

tasks.named<org.cyclonedx.gradle.CyclonedxDirectTask>("cyclonedxDirectBom") {
    includeConfigs.set(listOf("runtimeClasspath"))
}

tasks.withType<org.cyclonedx.gradle.BaseCyclonedxTask> {
    componentVersion.set(releaseVersion.orElse("unspecified"))
}
