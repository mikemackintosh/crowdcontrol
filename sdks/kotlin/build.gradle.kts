plugins {
    kotlin("jvm") version "1.9.23"
    application
}

group = "io.github.mikemackintosh"
version = "0.1.0"

repositories {
    mavenCentral()
}

kotlin {
    jvmToolchain(11)
}

dependencies {
    // ONLY kotlin-stdlib (implicit) — no other runtime dependencies.
    testImplementation(kotlin("test"))
}

application {
    mainClass.set("io.github.mikemackintosh.crowdcontrol.DemoKt")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

// Custom task to run the conformance runner.
tasks.register<JavaExec>("conformance") {
    group = "verification"
    description = "Run the CrowdControl conformance suite."
    classpath = sourceSets["main"].runtimeClasspath
    // The Kotlin file has @file:JvmName("ConformanceRunner"), so the
    // compiled class is ConformanceRunner (not the default *Kt variant).
    mainClass.set("io.github.mikemackintosh.crowdcontrol.ConformanceRunner")
}

// Custom task to run the demo.
tasks.register<JavaExec>("demo") {
    group = "application"
    description = "Run the CrowdControl demo."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("io.github.mikemackintosh.crowdcontrol.DemoKt")
}
