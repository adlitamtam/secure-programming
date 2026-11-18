# Stage 1: Build the JAR with Maven
FROM maven:3.9-eclipse-temurin-21 AS builder
WORKDIR /build

COPY pom.xml .
COPY src ./src
RUN mvn clean package

# Stage 2: Minimal Runtime Image (glibc-based for SQLite compatibility)
FROM eclipse-temurin:21-jre
WORKDIR /app

# Run as non-root user for container security
RUN useradd --create-home --shell /bin/bash passvault \
    && mkdir -p /app/data \
    && chown -R passvault:passvault /app

COPY --from=builder /build/target/passvault.jar /app/passvault.jar

USER passvault
WORKDIR /app/data

ENTRYPOINT ["java", "-jar", "/app/passvault.jar"]
