# Recon Secret Scanner

Async Python 3.10+ secret discovery scanner for bug bounty recon and security auditing pipelines.

## Highlights
- asyncio + `httpx.AsyncClient` with HTTP/2, retries, backoff, pooling, keep-alive, per-domain semaphores, circuit breaker
- 60+ regex signatures across AWS, SMTP, SaaS/API, payments, cloud, DB URIs, auth artifacts, crypto material
- Aho-Corasick keyword prefilter before regex evaluation
- Shannon entropy + mixity scoring
- multi-layer false-positive suppression
- TF-IDF + LogisticRegression contextual classifier with pickle persistence and LRU-cached scoring
- MinHash + LSH near-duplicate suppression
- scans HTTP responses, HTML/CSS comments, inline scripts, source maps (`sourcesContent`), framework debug endpoints
- soft-404 heuristics + DNS pre-resolution filtering
- output in JSON, SARIF 2.1.0, and HTML dashboard

## Usage
```bash
python -m secret_scanner.cli --url https://target.example --text-file .env
```

## Scanner une liste TXT de domaines/IPs
Crée un fichier `targets.txt` (une entrée par ligne):

```txt
example.com
api.example.com
1.2.3.4
https://already-qualified.example/path
# commentaires autorisés
```

Puis lance:

```bash
python -m secret_scanner.cli --url-file targets.txt
```

Par défaut, les entrées sans schéma sont testées en `https` puis `http`.
Tu peux changer avec:

```bash
python -m secret_scanner.cli --url-file targets.txt --schemes https
```


Notes: les entrées invalides (ex: `.` ou labels DNS vides) sont ignorées automatiquement au lieu de faire planter le scan.
