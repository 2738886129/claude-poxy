# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Claude Max reverse proxy server that enables sharing Claude access over a local network. It provides two main proxy modes:
1. **Web Proxy**: Proxies claude.ai web interface with authentication, fingerprint spoofing, and content filtering
2. **API Proxy**: Proxies Claude Code CLI API calls through local `claude` CLI commands

The proxy supports credential-based access control, admin management interface, and per-credential conversation/project isolation.

## Architecture

### Core Components

- **[src/index.ts](src/index.ts)**: Main entry point that orchestrates both proxy modes, authentication, and admin server
- **[src/auth.ts](src/auth.ts)**: Complete authentication system with API key management, encryption, and permission control
- **[src/webProxy.ts](src/webProxy.ts)**: Web proxy with fingerprint spoofing, conversation/project filtering, and HTML injection
- **[src/cliProxy.ts](src/cliProxy.ts)**: CLI proxy that spawns `claude` processes and converts responses to API format
- **[src/adminServer.ts](src/adminServer.ts)**: Admin panel for managing API keys and permissions (runs on separate port)
- **[src/staticCache.ts](src/staticCache.ts)**: LRU cache for static assets to reduce upstream requests

### Key Architecture Patterns

**Two-Server Architecture**: Main proxy server (port 3000/configurable) handles user traffic, separate admin server (port 3002) provides management interface accessible only from localhost.

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

**Process Pool Pattern**: `cliProxy.ts` uses a process pool to manage `claude` CLI subprocesses, with warmup on startup and streaming/non-streaming support.

**Fingerprint Spoofing**: The web proxy injects extensive JavaScript ([src/index.ts:147-887](src/index.ts#L147-L887)) to mask browser fingerprints including Canvas, WebGL, AudioContext, timezone, screen properties, and more. Can be disabled via `ENABLE_FINGERPRINT_SPOOFING` flag.

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
- `claude` CLI must be installed and logged in (`claude` command available)
- For web proxy: `CLAUDE_SESSION_KEY` in `.env` (get from claude.ai cookies)
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

Admin credentials skip all filtering (see [src/webProxy.ts:639-649](src/webProxy.ts#L639-L649) for chat example).

### CLI Proxy Message Format Conversion

The CLI proxy converts Messages API format to `claude` CLI format:
1. Extracts all messages including images ([src/cliProxy.ts:59-78](src/cliProxy.ts#L59-L78))
2. Converts to conversation format: "Human: {msg}\n\nAssistant: {msg}"
3. Spawns `claude` with `--output-format stream-json` or `text`
4. Converts CLI output back to Messages API SSE format ([src/cliProxy.ts:96-150](src/cliProxy.ts#L96-L150))

Images in Messages API are converted to data URLs and embedded in text.

### Static Cache Strategy

Cache configuration ([src/staticCache.ts:32-36](src/staticCache.ts#L32-L36)):
- Max size: 500MB
- Max age: 7 days
- LRU eviction when full
- Caches: JS, CSS, fonts, images, Next.js static assets
- Skips: API calls, React Server Components, Sentry

### Authentication Flow

1. User provides API key via Cookie (`proxy_key`), `Authorization` header, or `X-Proxy-Key` header
2. Middleware validates against hashed keys in `auth.json` ([src/auth.ts:210-224](src/auth.ts#L210-L224))
3. Checks if key has required permission: `web` (browser) or `api` (Claude Code)
4. Attaches `apiKeyEntry` to request for downstream filtering
5. Cookie expiration follows per-key `expiresInDays` setting

Admin panel uses separate `admin_session` cookie with password authentication.

### Critical Security Notes

- API keys stored AES-256-CBC encrypted in `auth.json`
- Admin password stored as SHA-256 hash
- Admin panel only accessible from `127.0.0.1`
- Fingerprint spoofing headers set on proxy requests ([src/webProxy.ts:356-360](src/webProxy.ts#L356-L360))
- CSP headers removed to allow script injection ([src/webProxy.ts:379-381](src/webProxy.ts#L379-L381))

## Common Patterns

### Adding New API Filters

To filter a new Claude API endpoint:
1. Add detection function (e.g., `isXyzApi()`) in [src/webProxy.ts](src/webProxy.ts)
2. Add handler in `proxyRes` event around line 377
3. Check `keyEntry.isAdmin` to skip filtering for admin
4. Use `getEffectiveAllowedList()` to get credential's whitelist
5. Apply `filterList()` or custom logic
6. Remember to update `content-length` header after modifying body

### Modifying Injected Scripts

Main injection point: [src/index.ts:142-888](src/index.ts#L142-L888)
- Admin mode uses `ADMIN_MINIMAL_SCRIPT` (crypto polyfill only)
- Normal mode uses `INJECT_SCRIPT` (polyfill + loads `/__proxy__/inject.js`)
- External script route: `/__proxy__/inject.js` (serves inline script)

To modify fingerprint spoofing, edit the inline script in `app.get('/__proxy__/inject.js', ...)` handler.

### Working with Process Pool

The CLI proxy maintains a pool of `claude` processes:
- Pool size: 3 (configurable in [src/cliProxy.ts:314](src/cliProxy.ts#L314))
- Warmup count: 1 process pre-started
- Each request spawns a new process (not reused due to claude CLI design)
- Streaming uses `--output-format stream-json`, non-streaming uses `text`

## Known Issues and Quirks

- React hydration warning (#418): Caused by script injection in HTML head, does not affect functionality
- `claude` CLI spawns with `--dangerously-skip-permissions` to avoid interactive prompts
- Fingerprint spoofing may cause false positives with Claude's fraud detection (can be disabled)
- Process pool "warmup" is a workaround for cold start latency
- Windows Ctrl+C handled specially via `SIGBREAK` signal

## Testing Approach

No automated tests currently. Manual testing workflow:
1. Start server: `npm run dev`
2. Test web proxy: Open `http://localhost:3000` with API key cookie
3. Test CLI proxy: Use Claude Code with `ANTHROPIC_BASE_URL=http://localhost:3000/v1`
4. Test admin panel: Open `http://localhost:3002` (localhost only)
5. Verify credential isolation by creating keys with different whitelists
6. Test admin mode by creating key with `isAdmin: true`
