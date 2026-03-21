# Flux Registry & CDN

A premium, standalone CDN and Asset Registry for remote bundles and static content.

## Features
- **Generic Backend**: Node.js + Express with lightweight JSON persistence.
- **Premium Admin UI**: Stunning dashboard with Glassmorphism and Lucide icons.
- **Micro-Frontend Ready**: Built-in support for remote bundle hosting and dev-mode overrides.
- **Automated Workflows**: Simple API for uploading, versioning, and serving assets.

## Getting Started

1. **Install Dependencies**:
   ```bash
   npm install
   ```

2. **Start the Service**:
   ```bash
   npm start
   ```
   The registry will be available at `http://localhost:3000`.

3. **Consume Assets**:
   Consumer applications can fetch `http://localhost:3000/assets` to retrieve the active registry.

## Admin API
- `GET /api/admin/assets`: List all registered assets.
- `POST /api/admin/assets`: Register a new asset.
- `PUT /api/admin/assets/:id`: Update asset configuration.
- `POST /api/admin/assets/:id/versions`: Upload a new version.
