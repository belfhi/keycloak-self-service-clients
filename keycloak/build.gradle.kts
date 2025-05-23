/*
 * This file was generated by the Gradle "init" task.
 *
 * This generated file contains a sample Java library project to get you started.
 * For more details on building Java & JVM projects, please refer to https://docs.gradle.org/8.7/userguide/building_java_projects.html in the Gradle documentation.
 */

group = "de.mixxplorer.keycloak.ssc"
version = "0.3.7"

val keycloakVersion by extra("26.1.4")

plugins {
    // Apply the java-library plugin for API and implementation separation.
    `java-library`
    checkstyle
    `maven-publish`
}

repositories {
    // Use Maven Central for resolving dependencies.
    mavenCentral()
    maven {
        url = uri("https://gitlab.desy.de/api/v4/projects/15228/packages/maven")
        name = "GitLab"
        credentials(HttpHeaderCredentials::class) {
            name = "Job-Token"
            value = System.getenv()["CI_JOB_TOKEN"]
        }
        authentication {
            create<HttpHeaderAuthentication>("header")
        }
    }
}

publishing {
    publications {
        create<MavenPublication>("library") {
            from(components["java"])
        }
    }
    repositories {
        maven {
            url = uri("https://gitlab.desy.de/api/v4/projects/15228/packages/maven")
            name = "GitLab"
            credentials(HttpHeaderCredentials::class) {
                name = "Job-Token"
                value = System.getenv()["CI_JOB_TOKEN"]
            }
            authentication {
                create<HttpHeaderAuthentication>("header")
            }
        }
   }
}

dependencies {
    implementation("org.keycloak:keycloak-services:$keycloakVersion")
    implementation("org.keycloak:keycloak-server-spi:$keycloakVersion")
    implementation("org.keycloak:keycloak-server-spi-private:$keycloakVersion")
    implementation("org.keycloak:keycloak-core:$keycloakVersion")
}

// Apply a specific Java toolchain to ease working on different environments.
java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

tasks.jar {
    archiveBaseName = "self-service-clients"
}
