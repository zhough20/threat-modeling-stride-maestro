# How to build a system model YAML (for the STRIDE + MAESTRO threat model)

## Purpose
A system model is a short, factual YAML description of one app: its components, data stores, data flows,
trust boundaries, outside parties, and any AI agents, tools, and models. `threatmodel.py` reads it, asks the decision model
narrow STRIDE/MAESTRO questions about each element, and code turns the answers into findings. The model is only as
good as what you write: **describe what the code actually does, not what it should do.** A security reviewer reviews every model.

## Where to put it
- One file per app: `<app-repo>/threat-model/system-model.yaml` (propose it in a PR; get reviewer approval before merge).
- Drafts outside a repo: `threat-model-drafts/<app>.yaml` in your own working folder.
- Schema: `system-model.schema.yaml` (same folder as this guide).

## Hard rules
1. **No secret values. Ever.** `secret_refs` holds env KEY NAMES only (e.g. `DATABASE_URL`), pattern `^[A-Z][A-Z0-9_]*$`.
   Don't paste `.env` contents, connection strings with passwords, tokens, or keys into any field. The runner masks
   anyway; that's a backstop, not permission.
2. **Mark unknowns, don't guess.** Start `description` with `UNKNOWN: <what>` (e.g. `UNKNOWN: whether auth is enforced on /admin`).
   If `exposure` or `data_classification` is unknown, pick the **more severe** value and say so in `description`.
   Only list a control in `controls` if you saw it in code/config.
3. **Hypothetical models set `system.example: true`.** Real apps omit it or set `false`.
4. **No extra fields.** Unknown keys fail validation.
5. **IDs** are lowercase `[a-z0-9_-]+`, unique, and every reference (`source`, `destination`, `tools`, `model`, `boundary`) must point to an existing id.

## Fields (exact, from the schema)
### Top level
| Field | Type | Required | Allowed / notes |
|---|---|---|---|
| `schemaVersion` | int | yes | must be `1` |
| `system` | object | yes | see below |
| `trust_boundaries` | list | no (recommended) | see below |
| `elements` | list | yes, ≥1 | see below |

### `system`
| Field | Type | Req | Notes |
|---|---|---|---|
| `name` | string | yes | app name |
| `owner` | string | yes | e.g. `team-payments`, `alice` |
| `example` | bool | no | `true` = hypothetical |
| `description` | string | no | one or two sentences on what the app does |

### `trust_boundaries[]`
| Field | Type | Req | Allowed |
|---|---|---|---|
| `id` | string | yes | `^[a-z0-9_-]+$` |
| `name` | string | yes | free text |
| `zone` | enum | yes | `internet`, `lan`, `host`, `container`, `third_party` |

### `elements[]` (common fields)
| Field | Type | Req | Allowed / when to use |
|---|---|---|---|
| `id` | string | yes | `^[a-z0-9_-]+$`, unique |
| `type` | enum | yes | `process` (your service/worker/CLI), `data_store` (DB, cache, bucket, file, vector DB), `data_flow` (data moving A→B), `external_entity` (users, 3rd-party systems you don't run), `agent` (LLM-driven loop that decides), `tool` (function an agent can call), `model` (LLM/embedding endpoint) |
| `name` | string | yes | human name |
| `description` | string | yes | ≤4000 chars. What it does, inputs, auth, how it's called. Facts only. Start with `UNKNOWN:` for gaps |
| `boundary` | string | no | a `trust_boundaries[].id` |
| `exposure` | enum | no (default `lan`) | `host_only` (localhost/socket), `lan`, `internet` |
| `data_classification` | enum | no (default `internal`) | `public`, `internal`, `pii`, `credentials` — highest class it handles |
| `controls` | list[string] | no | controls you **saw**, plain words (`session cookie auth`, `pydantic validation`, `TLS 1.2+`, `rate limit 10/s`) |
| `secret_refs` | list[string] | no | env KEY NAMES the element uses |

### `data_flow` only
| Field | Type | Notes |
|---|---|---|
| `source` | string | element id (**required** for flows) |
| `destination` | string | element id (**required** for flows) |
| `protocol` | string | `HTTPS`, `HTTP`, `gRPC`, `SQL/TCP`, `SSH`, `stdio`, ... |
| `crosses_boundary` | bool | true if source and destination are in different boundaries |

### `agent` only
| Field | Type | Notes |
|---|---|---|
| `autonomy` | enum | `read_only`, `suggests`, `acts_with_approval`, `acts_autonomously` |
| `tools` | list[string] | ids of `tool` elements it can call |
| `model` | string | id of its `model` element |
| `untrusted_inputs` | list[string] | text sources it reads that outsiders control (`ticket text`, `web pages`, `email`, `tool results`) |

## Finding elements in a codebase (what to grep)
Run with `rg -n` from the repo root. Read hits; don't copy values.
| Looking for | Grep |
|---|---|
| HTTP entry points (`process`, `exposure`) | `@(app|router)\.(get|post|put|patch|delete)\(`, `APIRouter\(`, `FastAPI\(`, `Flask\(`, `@app.route`, `uvicorn.run`, `--host 0.0.0.0` |
| Auth controls | `Depends\(`, `OAuth2`, `HTTPBearer`, `Security\(`, `verify_`, `jwt`, `session`, `api_key` |
| Validation | `BaseModel`, `Field\(`, `jsonschema`, `pydantic` |
| Data stores | `create_engine`, `sqlalchemy`, `psycopg`, `asyncpg`, `sqlite3`, `redis`, `boto3.*s3`, `chromadb`, `qdrant`, `pgvector`, `open\(.*["']w` |
| Raw SQL (Tampering) | `execute\(f"`, `execute\(.*%`, `text\(f"` |
| Outbound flows | `httpx\.`, `requests\.(get|post)`, `aiohttp`, `urllib.request`, `fetch\(`, `subprocess` |
| Secret KEY NAMES | `os\.environ\[`, `os\.getenv\(`, `environ\.get\(`, `Settings\(BaseSettings`, `\$\{[A-Z_]+\}` in compose; `.env.example` (names only — **never read `.env`**) |
| LLM / model calls (`model`, `agent`) | `openai`, `anthropic`, `model-gateway`, `ollama`, `ChatOpenAI`, `chat.completions`, `/v1/`, `:11434` |
| Tools / agent loops | `@tool`, `tools=\[`, `function_call`, `tool_choice`, `StructuredTool`, `mcp`, `Agent\(`, `AgentExecutor`, `crewai`, `langgraph` |
| Logging / audit | `logging.getLogger`, `structlog`, `audit` |
| Rate limits | `slowapi`, `Limiter`, `limit_req`, `timeout=` |
| Infra & boundaries | `docker-compose*.yml` (`ports:`, `networks:`, `volumes:`, `docker.sock`), `Dockerfile` (`USER`, `EXPOSE`), `*.tf` (`resource "`, `ingress`, `cidr_blocks`, `backend`), Caddy/nginx configs (TLS) |

Mapping tips: each container/network = a boundary candidate; `ports: "0.0.0.0:..."` or published ports → `exposure: lan` or `internet`;
every DB client → a `data_store` + a `data_flow` to it; every outbound call → `data_flow` + `external_entity` (or `model`);
an LLM loop that picks tools → `agent` + `tool`s + `model`.

## Minimal template
```yaml
schemaVersion: 1
system:
  name: my-app
  owner: example-team
  description: One sentence on what the app does.
trust_boundaries:
  - {id: internet, name: Public internet, zone: internet}
  - {id: app, name: App container, zone: container}
elements:
  - id: user
    type: external_entity
    name: End user
    description: Who calls the app and how they log in (or UNKNOWN:).
    boundary: internet
    exposure: internet
  - id: api
    type: process
    name: API service
    description: Routes, auth, validation as seen in code.
    boundary: app
    exposure: internet
    data_classification: internal
    controls: []
    secret_refs: []
  - id: f_user_api
    type: data_flow
    name: User to API
    description: What data moves.
    source: user
    destination: api
    protocol: HTTPS
    crosses_boundary: true
    exposure: internet
```

## Full annotated example
See `examples/example-fastapi-agent.yaml` (hypothetical, `example: true`). Highlights:
- `api` (process, internet, pii) lists only controls seen: session auth, pydantic, JSON logging; key name `APP_SESSION_KEY`.
- `db` (data_store, host_only) — ORM noted as a control; `DATABASE_URL` is a key name, not the URL.
- `summarizer` (agent) — `autonomy: acts_autonomously`, `tools: [lookup_order]`, `model: llm`, `untrusted_inputs: [ticket free text]`;
  its only "control" is a system prompt (MAESTRO L6 will flag that, correctly).
- `lookup_order` (tool) — description states "no per-user scoping" plainly so the decision model can judge it.
- `f_agent_llm` (data_flow) — `protocol: HTTP`, `crosses_boundary: true`, carries pii.

## Pre-submit checklist
- [ ] `schemaVersion: 1`, `system.name`, `system.owner` set; `example: true` only if hypothetical
- [ ] Every route group / worker / CLI is a `process`; every DB, cache, bucket, vector DB is a `data_store`
- [ ] Every DB client, outbound call, and agent→model call has a `data_flow` with `source`/`destination`/`protocol`
- [ ] Every LLM loop is an `agent` with `autonomy`, `tools`, `model`, `untrusted_inputs`
- [ ] `exposure` and `data_classification` set on everything (severe value + `UNKNOWN:` note if unsure)
- [ ] `controls` lists only what you saw in code/config
- [ ] `secret_refs` are KEY NAMES only; `rg -n '(sk-|ghp_|AKIA|BEGIN .*PRIVATE|://[^ ]+:[^ ]+@)' model.yaml` returns nothing
- [ ] Validate passes (below), then send to the security reviewer

## Validate
```bash
cd ~/Vault/Projects/_threat-modeling
.venv/bin/python threatmodel.py path/to/system-model.yaml --validate-only
# VALID: ... (N elements)  -> exit 0 ; input error: ... -> exit 2. Sends nothing, writes nothing.
```
