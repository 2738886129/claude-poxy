# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Claude Max reverse proxy server that enables sharing Claude web access over a local network. It proxies the claude.ai web interface with authentication, fingerprint spoofing, and content filtering.

The proxy supports credential-based access control, admin management interface, and per-credential conversation/project isolation.

## Architecture

### Core Components

- **[src/index.ts](src/index.ts)**: Main entry point that orchestrates the web proxy, authentication, and admin server
- **[src/auth.ts](src/auth.ts)**: Complete authentication system with API key management, encryption, and permission control
- **[src/webProxy.ts](src/webProxy.ts)**: Web proxy with fingerprint spoofing, conversation/project filtering, and HTML injection
- **[src/adminServer.ts](src/adminServer.ts)**: Admin panel for managing API keys and permissions (runs on separate port)
- **[src/staticCache.ts](src/staticCache.ts)**: LRU cache for static assets to reduce upstream requests

### Key Architecture Patterns

**Two-Server Architecture**: Main proxy server (port 3000/configurable) handles user traffic, separate admin server (port 3002) provides management interface.

**Credential Isolation**: Each API key has its own whitelist of allowed conversations and projects stored in `config.json`. Format:
```json
{
  "key_abc123": {
    "allowedChats": ["uuid1", "uuid2"],
    "allowedProjects": ["uuid3"]
  }
}
```

**Admin vs Normal Mode**: Admin credentials (`isAdmin: true`) bypass all content filtering and fingerprint spoofing, seeing the raw Claude interface. Normal credentials get filtered lists and browser fingerprint masking.

**Fingerprint Spoofing**: The web proxy injects extensive JavaScript to mask browser fingerprints including Canvas, WebGL, AudioContext, timezone, screen properties, and more. Can be disabled via `ENABLE_FINGERPRINT_SPOOFING` flag.

## Development Commands

### Build and Run
```bash
npm run build          # Compile TypeScript to dist/
npm run dev           # Development mode with hot reload (tsx watch)
npm start             # Production mode (runs compiled dist/index.js)
```

### Authentication Management
```bash
npm run auth          # Interactive auth CLI
npm run auth create "Name"                    # Create API key
npm run auth list                            # List all keys
npm run auth revoke <key_id>                 # Revoke a key
npm run auth set-admin-password              # Set admin panel password
npm run auth verify-admin-password           # Test admin password
```

### Setup Requirements
- Node.js >= 20.0.0
- `CLAUDE_SESSION_KEY` in `.env` (get from claude.ai cookies)
- For admin panel: Set admin password via `npm run auth set-admin-password`

### Configuration Files
- `.env`: Port, credentials path, session key (see [.env](.env) for structure)
- `config.json`: Per-credential whitelists (auto-managed, format documented above)
- `auth.json`: Encrypted API keys and admin password (auto-created)

## Important Implementation Details

### Web Proxy Response Interception

The web proxy intercepts specific API responses to filter content based on credential permissions:

- **Chat list API** (`/api/organizations/{org}/chat_conversations`): Filters to only show allowed conversations
- **Project list API** (`/api/organizations/{org}/projects_v2`): Filters to only show allowed projects
- **Search API** (`/api/organizations/{org}/conversation/search`): Filters search results by conversation UUID
- **Create APIs** (POST): Automatically adds new conversation/project UUIDs to creator's whitelist
- **Delete APIs** (DELETE): Automatically removes UUIDs from whitelist

Admin credentials skip all filtering (see `keyEntry.isAdmin` checks throughout [src/webProxy.ts](src/webProxy.ts)).

### Static Cache Strategy

Cache configuration ([src/staticCache.ts:31-36](src/staticCache.ts#L31-L36)):
- Max size: 500MB
- Max age: 7 days
- LRU eviction when full
- Caches: JS, CSS, fonts, images, Next.js static assets
- Skips: API calls, React Server Components, Sentry

### Authentication Flow

1. User provides API key via Cookie (`proxy_key`) or `X-Proxy-Key` header
2. Middleware validates against hashed keys in `auth.json` via `validateApiKey()`
3. Attaches `apiKeyEntry` to request for downstream filtering
4. Cookie expiration follows per-key `expiresInDays` setting

Admin panel uses separate `admin_session` cookie with password authentication.

### Critical Security Notes

- API keys stored AES-256-CBC encrypted in `auth.json`
- Admin password stored as SHA-256 hash
- Fingerprint spoofing headers set on proxy requests (User-Agent, Sec-CH-UA, Accept-Language)
- CSP headers removed to allow script injection

## Common Patterns

### Adding New API Filters

To filter a new Claude API endpoint:
1. Add detection function (e.g., `isXyzApi()`) in [src/webProxy.ts](src/webProxy.ts)
2. Add handler in `proxyRes` event
3. Check `keyEntry.isAdmin` to skip filtering for admin
4. Use `getEffectiveAllowedList()` to get credential's whitelist
5. Apply `filterList()` or custom logic
6. Remember to update `content-length` header after modifying body

### Modifying Injected Scripts

Main injection point: `app.get('/__proxy__/inject.js', ...)` in [src/index.ts](src/index.ts)
- Admin mode injects only `crypto.randomUUID` polyfill (see `ENABLE_FINGERPRINT_SPOOFING` flag)
- Normal mode injects full fingerprint spoofing + UI element hiding
- External script route: `/__proxy__/inject.js` (serves inline script with dynamic fingerprint config)

## Known Issues and Quirks

- React hydration warning (#418): Caused by script injection in HTML head, does not affect functionality
- Fingerprint spoofing may cause false positives with Claude's fraud detection (can be disabled)
- Windows Ctrl+C handled specially via `SIGBREAK` signal

## Testing Approach

No automated tests currently. Manual testing workflow:
1. Start server: `npm run dev`
2. Test web proxy: Open `http://localhost:3000` with API key cookie
3. Test admin panel: Open `http://localhost:3002`
4. Verify credential isolation by creating keys with different whitelists
5. Test admin mode by creating key with `isAdmin: true`
