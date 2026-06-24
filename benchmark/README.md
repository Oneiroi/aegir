# Aegir Latency Benchmark

Measures end-to-end p50/p95/p99 latency through a live Aegir instance across four scenario categories: **clean**, **pattern**, **suspicious**, and **hard-block**.

## Quick start

```bash
# 1. Start Aegir (in another terminal)
just run

# 2. Get a bearer token
TOKEN=$(curl -sk -X POST https://localhost:8443/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<your-admin-password>"}' \
  | jq -r .access_token)

# 3. Run the built-in benchmark
AEGIR_BENCH_TOKEN=$TOKEN just bench
```

## Scenario categories

| Category   | What triggers it          | Judge invoked? |
|------------|---------------------------|----------------|
| clean      | Benign requests           | No             |
| pattern    | IOC trie match            | No             |
| suspicious | Anomaly threshold crossed | **Yes**        |
| hard-block | Rule engine hard BLOCK    | No             |

The `suspicious` category latency is the judge-path cost. Compare it against `clean` to measure judge overhead.

## Comparing judge backends

Aegir's judge backend is configured in `aegir.yaml` (`judge.provider`). Run the benchmark once per backend to compare:

```bash
# Ollama (local)
AEGIR_BENCH_JUDGE=ollama AEGIR_BENCH_TOKEN=$TOKEN just bench

# OpenAI-compatible local (OMLX)
AEGIR_BENCH_JUDGE=omlx AEGIR_BENCH_TOKEN=$TOKEN just bench

# Anthropic (remote, requires ANTHROPIC_API_KEY in aegir.yaml)
AEGIR_BENCH_JUDGE=anthropic AEGIR_BENCH_TOKEN=$TOKEN just bench
```

`--judge-provider` is a **report label only** — the actual backend is determined by `aegir.yaml`. Restart Aegir between runs to switch backends.

## Replaying redteam attacks

The redteam attack catalog (`redteam/aegir/attack_catalog.yaml`) is a local-only file not included in the public repository. To use it:

```bash
# Extract payloads from the catalog into a plain text file
python3 -c "
import yaml
cat = yaml.safe_load(open('redteam/aegir/attack_catalog.yaml'))
for a in cat.get('attacks', []):
    if a.get('payload'):
        print(a['payload'])
" > /tmp/redteam-payloads.txt

# Run benchmark with the extracted payloads
AEGIR_BENCH_TOKEN=$TOKEN just bench-file PAYLOADS=/tmp/redteam-payloads.txt
```

Or use the convenience target:

```bash
AEGIR_BENCH_TOKEN=$TOKEN just bench-redteam
```

## Flags reference

| Flag              | Default                        | Description                              |
|-------------------|--------------------------------|------------------------------------------|
| `--target`        | `https://localhost:8443`       | Aegir base URL                           |
| `--token`         | (env `AEGIR_BENCH_TOKEN`)      | Bearer JWT for authentication            |
| `--payload-file`  | (built-in scenarios)           | One text payload per line                |
| `--iterations`    | `200`                          | Requests per scenario                    |
| `--concurrency`   | `10`                           | Parallel workers                         |
| `--judge-provider`| `ollama`                       | Label for report (does not change config)|
| `--insecure`      | `true`                         | Skip TLS verification (local dev)        |

## Interpreting results

```
CATEGORY               p50        p95        p99        max   statuses
----------------------------------------------------------------------------------
clean                  4ms        6ms        8ms       12ms   200×200
hard-block             2ms        3ms        4ms        6ms   403×200
pattern                3ms        5ms        7ms       10ms   403×200
suspicious           120ms      850ms     1400ms     2100ms   200×160 403×40
```

- `clean` p99 is your baseline (non-judge hot path). ISC-91 gate: <10ms.
- `suspicious` p95 is your judge-path cost. ISC-41 gate: <2000ms.
- `hard-block` should be faster than `pattern` (rule engine short-circuits before detection).
- `statuses` shows how many requests returned each HTTP status code.
