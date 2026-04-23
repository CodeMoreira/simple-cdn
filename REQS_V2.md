# simple-cdn: Requirements Version 2.0

This document outlines the structural changes and features for the next version of `simple-cdn`.

## 1. Architecture & Coding Standards

To ensure a scalable and maintainable system, the following principles must be strictly followed:

### 1.1 Core Principles
- **Language**: All code (variables, functions, classes), comments, and documentation must be in **English**.
- **SOLID**: Each component must follow SOLID principles to ensure robustness.
- **Ports and Adapters (Hexagonal Architecture)**: The system must be organized using Ports and Adapters to decouple business logic from external dependencies (database, file system, web server).
- **Small & Generic Parts**: Break files into small, reusable parts. Logic should be centralized to maintain a **Single Source of Truth**.

## 2. Persistence & Infrastructure

The system is evolving toward a more robust production-ready architecture.

### 2.1 Database
- **Migration**: The system must transition from JSON files (`registry.json`) to a real database.
- **Technology**: **SQLite** is the default choice for simplicity and portability.
- **Modeling**: Must support users, permissions, modules, versions, and deploy logs.

## 3. Authentication & Security System

A robust authentication flow is implemented to improve security and monitoring.

### 3.1 Users and Roles
- **Default Admin**: An `admin` user must exist by default for initial setup.
- **User Management**: Only the `admin` user has permission to register and manage other users via an administrative panel.
- **Password Reset by Admin**:
    - The `admin` can reset any user's password.
    - New passwords must be **randomly generated** by the system and provided to the user.
- **Profile Page**: All users have access to a profile page.
- **Password Change**:
    - Users can change their own passwords.
    - Confirming the current password is required.
    - **Password Rules**: Must be strict (e.g., minimum length, uppercase/lowercase, numbers, symbols).

## 4. Environment Workflow (Internal CI/CD)

The system manages three distinct environments with specific deployment rules.

### 4.1 Develop
- **Purpose**: The only environment that accepts external deployments (via API/CLI).
- **Versioning**: No history versioning. Each new deploy replaces (`replace`) existing files entirely.

### 4.2 Staging
- **Purpose**: Homologation environment.
- **Restriction**: Does not receive external deployments directly.
- **Workflow**: The `admin` (or delegated user) must manually trigger promotion from `develop` to `staging`.
- **Behavior**: Version is duplicated from `develop` to `staging`, replacing old content.

### 4.3 Production
- **Purpose**: Final consumption environment.
- **Restriction**: Does not receive external deployments directly.
- **Workflow**: The `admin` (or delegated user) must manually trigger promotion from `staging` to `production`.
- **Semantic Versioning**:
    - When promoting to `production`, a semantic version `x.x.x` (major.minor.patch) must be specified.
    - The new version must be higher than the current one.
- **Active Version**: The system allows setting any existing version in `production` as the "active version" for quick rollbacks.

### 4.4 Promotion Control (Permissions)
- **Delegation**: The `admin` can grant permissions to other users to accept deployments/promotions:
    - `develop` -> `staging` promotion.
    - `staging` -> `production` promotion.
- **Security Default**: By default, only the `admin` has these permissions.

### 4.5 Monitoring (Logs)
- Every deployment in any environment must log:
    - Timestamp of the operation.
    - Responsible user.

## 5. API & Tokens

### 5.1 Consumption & Admin APIs
- **Module Listing (`/modules`)**: 
    - Must return complete metadata for the consumer.
    - **Authentication**: This endpoint must support optional/mandatory `AuthToken` validation.
    - **Filtering**: The response must filter modules and versions based on the identity provided in the token (e.g., hidden modules or private environments).
- **Bundle Access (`/cdn/*`)**:
    - **Secure Resolution**: The `ScriptManager` resolver must be configured to inject the `Authorization: Bearer <token>` header into all bundle requests to ensure secure loading from the CDN.

## 6. Monitoring & Extensions

### 6.1 Visual Administrative Dashboard
- **UI/UX**: The system must provide a web dashboard for administrative tasks.
- **Design System**: Must follow a **Modern Dark Mode** aesthetic. Use high-contrast typography, subtle gradients, and clean borders. **Avoid glassmorphism**.
- **Features**:
    - **Deployment Timeline**: Visual history of who deployed what and when.
    - **One-Click Rollback**: Ability to switch the `active_version` of any module in `production` with a single click.
    - **User Audit**: View logs of administrative actions (password resets, permission changes).

### 6.2 Webhook Notifications
- **Events**: The system should support webhooks for critical events.
- **Payload**: Must send JSON data containing the module ID, version, environment, and the responsible user.
- **Triggers**: Promotion to `staging` or `production` must trigger a notification to integrated services (e.g., Slack, Discord).


### 5.2 Tokens
- **Purpose**: Replaces login/password in automated environments (e.g., `.env`).
- **Persistence**: Tokens do not expire.
- **Management**: Users can regenerate their tokens in the profile page.
- **Restricted Token Security**:
    - **Tokens for ANY user (including Admin) are restricted to `develop` deployments ONLY**.
    - Critical operations (promotions, user management, password changes) require session-based web authentication.
