# recon — pipeline de recon contínuo para bug bounty

Esqueleto modular em Python que orquestra ferramentas de recon, persiste tudo em
SQLite e **notifica só o que é novo** desde a última execução. Pensado para rodar
no cron e fazer monitoramento contínuo de escopo.

## Arquitetura

```
config.yaml            escopo, ferramentas, webhook
main.py                entrypoint (python main.py config.yaml)
recon/
  db.py                SQLite + upsert que devolve se a linha é NOVA
  scope.py             matching in/out-scope com wildcard
  runner.py            execução async das CLIs (stdin -> stdout JSONL)
  fetch.py             download concorrente de JS + .map (stdlib)
  notify.py            Discord webhook (só o delta)
  pipeline.py          orquestrador (lista ordenada de estágios)
  stages/
    base.py            Stage (ABC) + Context compartilhado
    subdomains.py      subfinder  (passivo)
    resolve.py         dnsx       (resolve + filtra wildcard)
    httpx_probe.py     httpx      (probing http: status/title/tech/cdn)
    urls.py            gau        (urls históricas)
    js_secrets.py      ponte p/ o motor Rust (fetch JS -> scan -> grava)
    verify.py          confirma se secrets estão vivos (probe read-only)
    nuclei_scan.py     nuclei     (vulns sobre os alvos vivos)
engine/
  js-secrets/          motor Rust de scan (CPU-bound)
    src/patterns.rs    catálogo + RegexSet (1 passada p/ N padrões)
    src/scan.rs        prefilter -> extração -> endpoints -> entropia
    src/sourcemap.rs   recupera sourcesContent do .map (código original)
    src/finding.rs     Finding + filtro de falso-positivo (allowlist)
    src/main.rs        manifest -> rayon -> JSONL no stdout
```

### A divisão Python / Rust

Fetch é I/O-bound e o escopo já vive no Python — então **Python baixa** os JS e
seus `.map`. Scan de N padrões sobre dezenas de milhares de arquivos é CPU-bound
— então **Rust varre**, via `RegexSet` (1 passada linear pra todos os padrões,
imune a ReDoS) + `rayon` (paralelo entre arquivos, sem GIL). Boundary: manifest
JSONL na entrada, findings JSONL na saída. Bench local deu **~40x** sobre loop
de regex ingênuo em Python — num único core.

O `.map` é o pulo do gato: `sourcesContent` carrega o código original (TS
inclusive) antes da minificação, então segredo picado no bundle volta legível.

### O modelo mental dos estágios

Cada estágio **lê do banco** o que o anterior produziu, roda sua ferramenta e
**grava de volta**. Não há DAG: uma lista ordenada resolve. Adicionar etapa é só
uma subclasse de `Stage` plugada em `pipeline.py`.

O coração é o `db._upsert()`: retorna `True` quando a linha não existia. É isso
que separa recon pontual de contínuo — a pipeline acumula o delta e notifica só
o que é novo.

## Compilar o motor

```bash
cd engine/js-secrets && cargo build --release
# binário em target/release/js-secrets (aponte em config.yaml -> js_secrets.binary)
```

## Rodar

```bash
pip install pyyaml
# instale as ferramentas (ProjectDiscovery): subfinder, dnsx, httpx, nuclei + gau
python main.py config.yaml
```

## Gerar config por programa

Cada programa de bug bounty vira um YAML (você codifica as regras dele uma vez).
Em vez de editar à mão, gere com defaults sensatos já aplicados:

```bash
python -m recon.init --program exemplo --in app.exemplo.com.br --handle leeo
# host único -> sem wildcard, seed garante a varredura, rate conservador

python -m recon.init --program acme --in "*.acme.com" --out blog.acme.com --handle leeo
# wildcard -> enumeração de subdomínio ativa
```

O gerador detecta wildcard vs host único e avisa o que cada um implica; também
alerta se você passar uma URL onde devia ir só o host. Para ajuste fino manual,
`template.yaml` traz todos os campos comentados.

Sem webhook configurado a notificação vira no-op. Sem alguma ferramenta no PATH,
o estágio correspondente loga erro e a pipeline segue.

## Onde está o *edge* (próximos passos)

- **AWS pareado** — `AKIA` sozinho não verifica; correlacionar com o secret key
  no mesmo arquivo e fazer STS GetCallerIdentity (read-only, canônico).
- **Templates nuclei custom** — o público todo mundo roda; o seu acha bug.
- **Inline source maps** (`data:` base64) — hoje o fetch ignora; dá pra decodar.
- **Permutação de subdomínios** — gotator/dnsgen entre `subdomains` e `resolve`.
- **Port scan** — naabu antes do httpx pra serviços fora de 80/443.
- **Diff histórico** — a tabela `runs` já guarda timestamps; query em `first_seen`
  responde "o que apareceu nos últimos 7 dias?".

## Verificação (estágio `verify`)

Confirma quais secrets estão de fato vivos via probe read-only do tipo "whoami".
**Contrato: verificar nunca é explorar** — uma chamada que só confirma que a
credencial autentica, sem enumerar/ler/modificar recurso. Webhooks nunca são
verificados (verificar = postar no canal de alguém). Tipos sem probe seguro
(AWS isolado, Google API key, private key) viram `unsupported` p/ triagem manual.

Verificadores com probe de rede: github, gitlab, stripe, sendgrid, slack, npm.
Offline: jwt (decodifica e checa expiração; não valida assinatura). Adicionar
provider = uma função em `recon/verify.py` registrada em `VERIFIERS`.

> Uso restrito a alvos dentro do escopo de programas que autorizam teste.
