# xSight Web UI

Vue 3 + Vite + Element Plus single-page application for the xSight Controller.

## Stack

- **Vue 3** with `<script setup>` SFCs
- **Element Plus** — UI component library
- **ECharts** (vue-echarts) — traffic charts
- **Pinia** — state management
- **vue-i18n** — English / Chinese localization
- **Axios** — HTTP client

## Themes

- **Classic** — Stripe-inspired light theme (purple accent)
- **Amber** — Retro terminal theme with DSEG14 14-segment LCD font (green phosphor digits)

## Development

```bash
npm install
npm run dev       # http://localhost:5173 (Vite dev server)
```

## Production Build

```bash
npm run build     # outputs to dist/
```

The `dist/` directory is embedded into the Controller Go binary via `go:embed`. After building the frontend, rebuild the Controller binary to include the new assets.
