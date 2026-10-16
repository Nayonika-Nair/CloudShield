# Running CloudShield

See the project [README](../README.md) for the full guide. Short version:

```bash
cp .env.example .env            # set POSTGRES_PASSWORD, JWT_SECRET_KEY and the account passwords
docker compose up --build       # UI http://localhost:3000, API http://localhost:8000/docs
docker compose down             # stop (data stays in the cloudshield-pgdata volume)
```

Without Docker: install `backend/requirements-dev.txt`, point `DATABASE_URL` at PostgreSQL (or `sqlite:///./dev.db`), set `JWT_SECRET_KEY` and `ADMIN_EMAIL`/`ADMIN_PASSWORD`, then run `uvicorn app.main:app` from `backend/` and open http://localhost:8000.

The application now uses the Fake AWS simulator; the original static prototype and mock provider are retained only for regression tests.
