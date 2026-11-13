FROM eclipse-temurin:25-jre-noble@sha256:a98128a57de944a72bd31fbc79b898edd5a5864d3652071d5bbd2160ab7d7dce

RUN apt-get update \
    && apt-get install -y --no-install-recommends softhsm2 curl \
    && rm -rf /var/lib/apt/lists/*

COPY softhsm/generated/tokens/ /var/lib/softhsm/tokens/

WORKDIR /app

ARG APP_JAR=wallet-backend.jar
COPY build/libs/${APP_JAR} /app/main.jar

CMD ["java", "--enable-native-access=ALL-UNNAMED", "-jar", "/app/main.jar"]

EXPOSE 8080
