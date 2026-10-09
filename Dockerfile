# signer — serviço interno de assinatura (Java 21 + Demoiselle Signer).
# Build com Maven no primeiro estágio; o runtime só tem a JRE, o jar e as dependências.
# Imagens base pelo espelho do Google (mirror.gcr.io): o pull anônimo do Docker Hub
# esbarra no limite de taxa nos runners da CI. Mesmas imagens oficiais (library/).
FROM mirror.gcr.io/library/maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
RUN mvn -B -q -DskipTests package

FROM mirror.gcr.io/library/eclipse-temurin:21-jre
RUN useradd --system --uid 10001 --home-dir /app signer \
 && mkdir -p /app /dev-pki \
 && chown signer /dev-pki
WORKDIR /app
COPY --from=build /src/target/signer.jar /app/signer.jar
COPY --from=build /src/target/lib /app/lib
USER signer
ENV SIGNER_PORT=8090
EXPOSE 8090
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/signer.jar"]
