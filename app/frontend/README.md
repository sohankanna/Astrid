# AI SOC Command Center (analyst console)

React + TypeScript + Vite. Talks only to the local SOC API (`/api`, proxied
to `127.0.0.1:8000`). No external assets, fonts, CDNs or hosted APIs.

```bash
npm install          # once
npm run dev          # http://127.0.0.1:5173
npm run build        # type-check + production build
```

Start the backend first: `app/.venv/Scripts/python.exe -m app.api` from the repo root.
