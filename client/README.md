# Sentinel Security Dashboard

React dashboard for the NestJS repository scanner.

## Development

Start the backend from the repository root with `npm run start:dev`, then run:

```bash
npm install
npm run dev
```

The Vite proxy forwards `/api` to `http://localhost:3001`. Override the target
with `API_PROXY_TARGET` in a local `.env` file if needed. The dashboard reads
repositories through the backend; private repository access requires the
backend's `GITHUB_TOKEN`. Do not add GitHub credentials to frontend environment
variables.

## Checks

```bash
npm run build
npm run test
npm run lint
```
