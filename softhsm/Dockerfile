FROM eclipse-temurin:25-jre-noble@sha256:3f2223fe04b750aa5a8179e29b5c9a1ddf7665fc9bb08bfe11ad01d143bc13a5

RUN apt-get update \
    && apt-get install -y --no-install-recommends softhsm2 curl \
    && rm -rf /var/lib/apt/lists/*

COPY softhsm/generated/tokens/ /var/lib/softhsm/tokens/

WORKDIR /app

ARG APP_JAR=wallet-backend.jar
COPY build/libs/${APP_JAR} /app/main.jar

CMD ["java", "--enable-native-access=ALL-UNNAMED", "-jar", "/app/main.jar"]

EXPOSE 8080
