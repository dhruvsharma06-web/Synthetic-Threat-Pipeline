# Setup & operations guide

Detailed setup, the Compose profiles, and troubleshooting. For the fast path see the
[README](README.md) quick start.

## 1. Requirements

| | |
|---|---|
| CPU | 4+ cores |
| RAM | 8 GB for the `range` profile; 16 GB if you also run the `soc` (Wazuh) profile |
| Disk | 20 GB free, SSD recommended (high log volume) |
| Software | Docker Desktop (WSL2 backend on Windows), Python 3.11+, Git, Node 18+ for the dashboard |

## 2. Install

```bash
git clone https://github.com/dhruvsharma06-web/Synthetic-Threat-Pipeline.git
cd Synthetic-Threat-Pipeline
cp .env.example .env            # fill in passwords — .env is gitignored, never commit it
pip install -r requirements.txt
```

## 3. Compose profiles

`docker-compose.yml` is one file with three profiles, so you boot only what you need:

| profile | brings up | cost |
|---------|-----------|------|
| `range` | the honeypots (Cowrie, VSFTPD, DVWA, sar2html, Flask victim) | light |
| `soc`   | Wazuh indexer / manager / dashboard | heavy (~8 GB RAM) |
| `ui`    | Loki + Promtail + Grafana log stack and the dashboard | medium |

```bash
docker compose --profile range up -d                                  # honeypots only
docker compose --profile range --profile ui up -d                     # + log stack + dashboard
docker compose --profile range --profile soc --profile ui up -d       # everything
docker compose down -v                                                # stop and wipe volumes
```

Allow 3–5 minutes for the `soc` profile to initialise. Admin ports bind to `127.0.0.1`
only; the honeypot network blocks outbound traffic.

## 4. Generate traffic

```bash
python -m bots.scheduler --dry-run                                  # preview the schedule
python -m bots.scheduler --hours 8 --seed 1 --attack-ratio 0.5      # overnight labelled run
python -m bots attackers.ssh_brute --bot-id demo-1 --duration 60    # run a single bot
```
Each run appends a ground-truth label row the pipeline joins against. Benign and attacker
bots run concurrently so the dataset has both classes.

## 5. Build, train, serve

```bash
make dataset     # logs → common schema → label join → features.parquet + data_card.json
make train       # baselines + models → model.joblib + model_card.json
make test        # full test suite
make lint        # ruff

uvicorn pipeline.api:app --port 8000     # scoring API (http://localhost:8000/health)
python -m controller.brain                # Loki worker: tails logs and scores live
cd frontend-simple && npm install && npm run dev
```

## 6. Troubleshooting

- **FTP/SSH bots fail to log in** — the honeypot accounts must exist in the containers;
  tune bot credentials once the range is up (the placeholders assume default accounts).
- **`make dataset` finds nothing** — logs land under `logs/<source>/`; confirm the range
  is writing there and `config.yaml`'s `log_dir` matches.
- **Dashboard shows "scorer offline"** — the API isn't running or `VITE_API_URL` is wrong.
- **`make train` says `insufficient_labelled_data`** — no attack labels yet; run the bots,
  rebuild the dataset, retrain.
- **Wazuh dashboard won't start** — the `soc` profile needs the full RAM; check
  `docker compose logs wazuh.manager`.
