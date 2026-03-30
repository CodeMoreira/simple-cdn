# Flux Registry & CDN

A premium, standalone CDN and Asset Registry for remote bundles and static content.

- **Registry Dual-Track**: Supports both versioned Production bundles and ephemeral Cloud-Dev bundles.
- **Premium Admin UI**: Stunning dashboard with Glassmorphism and Lucide icons.
- **Zephyr-Style Sync**: Atomic "Dev-Push" endpoint for rapid cloud-based previewing.
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
   Consumer applications (SuperApp Hosts) fetch `http://localhost:3000/modules` to retrieve the registry with both `active_version_url` and `dev_url`.

## Admin API
- `GET /api/admin/modules`: List all registered modules.
- `POST /api/admin/modules`: Register a new module.
- `PUT /api/admin/modules/:id`: Update module configuration.
- `POST /api/admin/modules/:id/versions`: Upload a production version.
- `POST /api/admin/modules/:id/dev`: Upload a Cloud-Dev sync bundle (Overwrites dev track).
