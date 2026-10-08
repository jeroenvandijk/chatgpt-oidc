# ChatGPT OIDC client

A CLI implementing OpenAI's official **Sign in with ChatGPT** flow for eligible open-source/local applications. Set `CHATGPT_AGENT_NAME` if you want the registration display name to differ from the default `ChatGPT OIDC CLI`.

It does **not** scrape or reuse ChatGPT web-session cookies/tokens and does not call ChatGPT private `backend-api` endpoints. The OAuth token it obtains is for eligible requests to the public OpenAI API resource `https://api.openai.com/v1`.

## Requirements

- Babashka >= 1.13.225 (a current release is recommended)
- A browser on the same machine for interactive sign-in
- An eligible ChatGPT account for ChatGPT-plan-backed API usage

No third-party Babashka dependencies are required.

## Use

```bash
bin install io.github.jeroenvandijk/chatgpt-oidc
```

To place the access token in an environment variable without printing extra status text:

```bash
export ACCESS_TOKEN="$(chatgpt-oidc token)"
```

The `token` command refreshes automatically when the access token is close to expiry.

Other commands:

```bash
chatgpt-oidc refresh
chatgpt-oidc logout
```

## Credential storage

Credentials are stored in `~/.config/chatgpt-oidc/auth.edn`; the stable machine host ID is kept separately in `~/.config/chatgpt-oidc/host.edn`.

On POSIX filesystems the client attempts to set both files to mode `0600`. `auth.edn` contains access, refresh, and ID tokens, so treat it as a secret and never commit or log it. `logout` attempts to revoke the saved refresh token with OpenAI, then clears access/refresh/ID tokens locally. It retains the stable host ID and the non-secret issued client-ID/account mapping so a later login can reuse the same app registration. If the network revocation cannot be confirmed, the CLI still clears local tokens and prints a warning.

## What the login flow does

1. Creates and persists a stable `ext_agent_host_id` for this machine.
2. Starts a loopback callback on `127.0.0.1` using `/auth/callback`.
3. Generates fresh OAuth `state`, OIDC `nonce`, and PKCE verifier/challenge.
4. On first login uses `client_id=dynamic_agent_client`; OpenAI returns an issued `oaiapp_...` client ID in the callback.
5. Exchanges the authorization code with PKCE at the OpenAI token endpoint.
6. Verifies the ID-token RS256 signature against OpenAI's JWKS, then validates issuer, audience, expiry, nonce, and subject.
7. Requires the granted `chatgpt.tokens.use.direct` scope before saving credentials.
8. Reuses the issued client ID on later logins and refreshes. Returning logins use the saved email as a login hint; bearer/ID tokens are never put in the printed authorization URL.

## Example API use

The token is intended for the public API, not the ChatGPT web backend. For this ChatGPT-plan flow, follow OpenAI's current Responses API constraints. For example, requests are expected to use `store: false` and `stream: true`, and a model available to the signed-in account.

## Concurrency note

OpenAI refresh tokens rotate. Avoid running multiple `token`/`refresh` commands concurrently against the same credential file; serialize refreshes if you wrap this CLI in a larger process supervisor.
