# signer — serviço interno de assinatura (Java 21 + Demoiselle Signer).
# Build com Maven no primeiro estágio; o runtime só tem a JRE, o jar e as dependências.
# Imagens base pelo espelho do Google (mirror.gcr.io): o pull anônimo do Docker Hub
# esbarra no limite de taxa nos runners da CI. Mesmas imagens oficiais (library/).
# Fixadas por digest (o que a tag apontava em 2026-10-13): maven:3.9.9-eclipse-temurin-21 e
# eclipse-temurin:21-jre. Para renovar: docker pull <imagem:tag> e
# docker inspect --format '{{index .RepoDigests 0}}' <imagem:tag>; troque aqui e em bin/mvn.
FROM mirror.gcr.io/library/maven@sha256:3a4ab3276a087bf276f79cae96b1af04f53731bec53fb2e651aca79e4b10211e AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
RUN mvn -B -q -DskipTests package

FROM mirror.gcr.io/library/eclipse-temurin@sha256:cff19e6215689161eb6162c11b86b0c60ddf802164f2eaf48d570f8fb79a36c5
# ~/.signer: o Demoiselle guarda ali o pacote de âncoras da ICP-Brasil que baixa do ITI/Serpro
# (destinos fixos); sem poder gravar, baixaria de novo a cada certificado fora do cache.
RUN useradd --system --uid 10001 --home-dir /app signer \
 && mkdir -p /app /dev-pki /app/.signer \
 && chown signer /dev-pki /app/.signer
WORKDIR /app
COPY --from=build /src/target/signer.jar /app/signer.jar
COPY --from=build /src/target/lib /app/lib
USER signer
ENV SIGNER_PORT=8090
EXPOSE 8090
# Liveness pelo /livez (sem token e sem dado); a imagem não tem curl.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["java", "-cp", "/app/signer.jar", "rotasaude.signer.HealthProbe"]
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/signer.jar"]
