# Secure Review Portal

React + TypeScript + Vite frontend for the FastAPI review service.

## Local development

From `frontend/`:

```powershell
npm install
npm run dev
```

Vite is configured with `envDir: ".."`, so local development reads the ignored root `.env.local`. Copy [`.env.example`](.env.example) to a local environment file when setting up another workspace.

Required browser variables:

- `VITE_SUPABASE_URL`
- `VITE_SUPABASE_PUBLISHABLE_KEY`
- `VITE_API_BASE_URL` (defaults to `http://127.0.0.1:8000`)

The publishable key is browser configuration only. Never add service-role keys, database credentials, JWT signing secrets, or LLM keys to `VITE_` variables.

## Checks

```powershell
npm run test
npm run lint
npm run build
```

The frontend uses the real authenticated API routes under `/api/v1`: review creation, review history, review details, findings, job status, and deletion. It does not invent progress or findings. Live Supabase Auth requires a configured Supabase project and is not proven by the mocked/unit frontend tests.
