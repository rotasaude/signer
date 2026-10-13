# signer — assinatura ICP-Brasil do Rota Saúde

Serviço interno, sem estado e sem banco (ADR 0032, módulo 19b). O `api` conduz o
fluxo (OAuth com o PSC, sessões, fila); o `signer` **prepara**, **monta** e
**valida** assinaturas AD-RB:

- CAdES destacado sobre o JSON canônico (`contracts/clinical`);
- PAdES sobre o PDF da consulta (assinatura invisível; o rodapé NGS2 vem desenhado pelo `api`).

O hash é assinado fora, pelo certificado em nuvem do profissional (API de PSC do
ITI, DOC-ICP-17.01, `signature_format: RAW`). O documento nunca sai da
infraestrutura e o `signer` nunca grava documento.

## Como funciona

| Rota | Faz |
|---|---|
| `POST /prepare` | Monta os atributos assinados da política (Demoiselle, sem chave privada) e devolve o SHA-256 que vai ao PSC e um `prepared_state` opaco (selado com HMAC). Em PAdES, reserva a assinatura no PDF e grava a hora (entrada `M`). |
| `POST /assemble` | Confere a RAW contra o certificado (PKCS#1 v1.5 SHA-256 sobre os atributos), monta o CMS (BouncyCastle) e devolve o `.p7s` ou o PDF assinado, mais o material de validação (cadeia + LCRs do ato, CMS certs-only). |
| `POST /verify` | Valida no servidor (NGS2.03): criptografia e atributos (checker do Demoiselle), política AD-RB, cadeia até âncora confiável, hora da assinatura dentro da validade, keyUsage e revogação no instante da assinatura. `valid`, `invalid` ou `indeterminate`, com motivos. |
| `POST /certificates/check` | Confere o certificado no vínculo: cadeia até âncora confiável, validade agora, keyUsage e LCR, com os mesmos motivos do `/verify`; devolve `status`, `signer_cpf`, `not_after`, `reasons`. DER ilegível ou chave não RSA → 422 `invalid_certificate`. |
| `GET /health` | Versão e hora do último download de LCR bem-sucedido. |

Formas e erros: `docs/superpowers/plans/2026-10-08-module-19b-signature-contracts.md` §9
(repo `docs`). Toda rota, exceto `/dev-pki/*` (só dev), exige `Authorization: Bearer $SIGNER_TOKEN`. O corpo da requisição é limitado a 48 MB; no `/prepare`, um PDF preparado acima de 32 MiB é recusado com 400 `invalid_request` (o `prepared_state` não caberia no `/assemble`).

Políticas (padrões do Demoiselle Signer 4.6.2, lidas do `.der` da política no jar):
CAdES AD-RB v2.4 (`2.16.76.1.7.1.1.2.4`) e PAdES AD-RB v1.3 (`2.16.76.1.7.1.11.1.3`).
O `/verify` aceita todas as versões AD-RB do formato.

Motivos do `/verify`: `malformed_signature`, `signature_mismatch`, `untrusted_chain`,
`policy_mismatch`, `signing_time_missing`, `certificate_expired`, `key_usage`,
`certificate_revoked`, `pdf_modified_after_signing` (todos `invalid`);
`revocation_unavailable` e `certificate_revoked_after_signing` (sozinhos, `indeterminate`);
outros códigos do Demoiselle aparecem em minúsculas.

## Estado da prova com PSC real

A prova com um PSC real (sandbox VIDaaS + `validar.iti.gov.br`) **não foi feita**. Ela é o
gate de go-live `rotasaude/api#53`. Dev e staging rodam contra a AC de teste (`DevPki`) e o PSC simulado.

## Configuração

| Variável | Padrão | O que é |
|---|---|---|
| `SIGNER_TOKEN` | — (obrigatório, ≥ 32 caracteres) | Token compartilhado com o `api`/worker; também deriva a chave do `prepared_state`. |
| `SIGNER_PORT` | `8090` | Porta HTTP. |
| `SIGNER_ENV` | — (obrigatório) | `development`, `staging` ou `production`, exatamente assim (minúsculas); ausente, vazia ou outro valor = o boot falha (saída 1). Também é variável do próprio Demoiselle: `production` desliga as cadeias de homologação da ICP-Brasil. Aqui, `production` também proíbe as duas abaixo e a propriedade `-Dsigner.extraTrustAnchors` (por exemplo via `JAVA_TOOL_OPTIONS`); o boot falha. |
| `SIGNER_EXTRA_TRUST_ANCHORS` | — | PEM com âncoras extras (AC de teste/dev). Nunca em produção. |
| `SIGNER_DEV_PKI_DIR` | — | Diretório da AC de desenvolvimento; liga `GET /dev-pki/{root.crl,intermediate.crl}` sem token. Nunca em produção. |
| `SIGNER_MAX_CONCURRENCY` | `8` | Operações simultâneas (`/prepare`, `/assemble`, `/verify`, `/certificates/check`). O excesso recebe 503 `{"error":"busy"}` com `Retry-After: 1`; o `api` trata como indisponível e tenta de novo. `/health` e `/livez` não entram na conta. |
| `SIGNER_CRL_CACHE_MAX_SECONDS` | `3600` | Idade máxima da LCR no cache em memória (vale o menor entre isso e o `nextUpdate`). `0` desliga o cache. |
| `SIGNER_CRL_CONNECTION_TIMEOUT` | `5000` | Timeout (ms) de conexão e de leitura do download de LCR. |

Rede de saída: só as LCRs das ACs (pontos de distribuição dos certificados). As LCRs são autenticadas (assinatura do emissor, DN do emissor, `thisUpdate`/`nextUpdate`); No `/verify` e no `/certificates/check`, LCR inautêntica, vencida ou indisponível resulta em `indeterminate`, nunca em `valid`. No `/prepare` a revogação é conferida antes de montar os atributos: certificado revogado → 422 `invalid_certificate`; LCR inautêntica, vencida ou indisponível → 500 `internal` (transitório: o `SignJob` do `api` tenta de novo), nunca 422.
Todo download de LCR (o nosso e o do checker do Demoiselle) passa pelo `CrlFetcher`: só `http`/`https`, sem seguir redirecionamento, corpo de no máximo 10 MiB e, com `SIGNER_ENV=production`, nunca para endereço interno (loopback, privado, link-local, ULA). No `/verify`, certificado sem cadeia confiável é recusado (`untrusted_chain`) **antes** de qualquer download de LCR ou de qualquer destino tirado do certificado, e sem `signer_cpf`/`signer_name` na resposta. Fora disso, a única rede de saída é a do próprio Demoiselle para atualizar as âncoras da ICP-Brasil (destinos fixos do ITI e do Serpro); o pacote fica em `~/.signer` (`/app/.signer` na imagem). Sem rede, o signer sobe com as âncoras embutidas.
Variáveis do Demoiselle que valem aqui: `SIGNER_PROXY_*`, `SIGNER_DISABLE_CHAIN_<CADEIA>`.

## Operação

- `GET /livez` (sem token): `ok`. É o que o `HEALTHCHECK` da imagem consulta (`rotasaude.signer.HealthProbe`, sem curl).
- `GET /health` (com token): `version`, `crl_updated_at` (último download de LCR bem-sucedido), `revocation_unavailable_count` (falhas de LCR desde a partida) e `revocation_unavailable_since` (início da sequência de falhas atual; `null` quando a última tentativa deu certo).
- Log `WARN revocation_unavailable host=<host>`: LCR indisponível, no máximo uma linha por host por minuto. Persistindo, as verificações saem `indeterminate` e o `/prepare` responde 500.
- A partida falha (saída 1) sem nenhuma âncora de confiança carregada.

## Logs

Só o acesso: método, caminho, status e duração. Corpo de requisição, token, CPF,
nome e texto clínico nunca vão ao log. O Demoiselle fica **desligado** no
`log4j2.xml` porque escreve o DN do titular (nome e CPF). O teste
`SignerServerTest#logsNeverCarryTokenCpfNameOrDocument` quebra se isso mudar.

## Desenvolvimento

O host não precisa de Maven: `bin/mvn` roda o Maven 3.9 com JDK 21 num container.

```bash
bin/mvn test      # JUnit: AC de teste gerada no próprio teste (DevPki), LCR servida localmente
bin/mvn verify    # o mesmo da CI
docker build -t rota-saude/signer:dev .
```

No compose do monorepo o serviço chama `signer` (porta 8090; no host só em
`127.0.0.1:${SIGNER_HOST_PORT:-8090}`). Em dev, o container gera na primeira
subida uma AC de teste no formato ICP-Brasil no volume `signer-dev-pki`
(`anchors.pem`, `root.pem`, `intermediate.pem`, `intermediate.key.pem`,
`root.crl`, `intermediate.crl`) e confia nela. O `api` monta o mesmo volume em
`/signer-dev-pki` para o PSC falso emitir e-CPF de teste com a chave da
intermediária. Para recomeçar a AC: `docker compose rm -sf signer && docker volume rm rota-saude_signer-dev-pki`
(assinaturas de dev feitas com a AC antiga passam a `invalid`/`untrusted_chain`).

## Dependências e licenças

- Demoiselle Signer 4.6.2 (Serpro, LGPL-3.0): políticas ICP-Brasil, cadeias, atributos, checker. Usado como biblioteca, sem alteração.
- BouncyCastle 1.80 (MIT): o `SignerInfo` com a assinatura calculada fora — o Demoiselle não assina em duas fases sem chave privada.
- Apache PDFBox 3 (Apache-2.0): a estrutura de assinatura do PDF — o Demoiselle não manipula PDF.
- Jackson e Log4j 2 (Apache-2.0).
