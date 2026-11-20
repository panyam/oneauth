// An MCP server on the official TypeScript SDK (@modelcontextprotocol/sdk),
// for the MCP server-auth conformance suite (oneauth issue 521).
//
// oneauth-server is the authorization server, and the TS SDK is the
// resource server: its requireBearerAuth middleware gates /mcp and writes
// the 401 and 403 challenges, and its mcpAuthMetadataRouter serves RFC 9728
// and RFC 8414 discovery. The token verifier checks signature, iss and aud
// against oneauth-server's JWKS with jose. So this run checks interop, a TS
// resource server accepting oneauth's tokens and metadata, rather than
// oneauth's own resource-server code (that is the gosdk run).
//
// Env: PORT, AS_URL, MCP_URL, BOOTSTRAP_FILE (the JSON cmd/bootstrap wrote).
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import express from 'express';
import { rateLimit } from 'express-rate-limit';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { mcpAuthMetadataRouter, getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';

const port = Number(process.env.PORT ?? 18300);
const asURL = process.env.AS_URL ?? 'http://localhost:18200';
const mcpURL = new URL(process.env.MCP_URL ?? `http://localhost:${port}/mcp`);
const tokens = JSON.parse(readFileSync(process.env.BOOTSTRAP_FILE!, 'utf8'));

// Must match tests/mcpauth/fixture: tool -> the scope it needs.
const toolScopes: Record<string, string> = { 'write-tool': 'write', 'admin-tool': 'admin' };
const scopesSupported = ['read', 'write', 'admin'];

const jwks = createRemoteJWKSet(new URL(`${asURL}/.well-known/jwks.json`));
const verifier: OAuthTokenVerifier = {
  async verifyAccessToken(token) {
    try {
      const { payload } = await jwtVerify(token, jwks, { issuer: asURL, audience: mcpURL.href });
      const scopes = Array.isArray(payload.scopes) ? (payload.scopes as string[]) : String(payload.scope ?? '').split(' ').filter(Boolean);
      return {
        token,
        clientId: String(payload.client_id ?? payload.sub ?? ''),
        scopes,
        expiresAt: payload.exp,
        resource: mcpURL
      };
    } catch (err) {
      throw new InvalidTokenError(err instanceof Error ? err.message : String(err));
    }
  }
};

function newServer(): McpServer {
  const server = new McpServer({ name: 'oneauth-ts-fixture', version: '1.0.0' });
  server.registerTool(
    'echo',
    { description: 'Echoes its input; needs a valid token and no scope', inputSchema: { message: z.string().optional() } },
    async ({ message }) => ({ content: [{ type: 'text', text: `echo: ${message ?? ''}` }] })
  );
  for (const [name, scope] of Object.entries(toolScopes)) {
    server.registerTool(name, { description: `Needs the ${scope} scope` }, async () => ({
      content: [{ type: 'text', text: `${name} ok` }]
    }));
  }
  return server;
}

const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(mcpURL);
const oauthMetadata = await (await fetch(`${asURL}/.well-known/oauth-authorization-server`)).json();

const app = express();
// The scenarios send a few hundred requests a run; the limit only keeps a
// stray client from hammering a long-lived fixture.
app.use(rateLimit({ windowMs: 60_000, limit: 2000, standardHeaders: 'draft-8', legacyHeaders: false }));
app.use(express.json());
app.use(mcpAuthMetadataRouter({ oauthMetadata, resourceServerUrl: mcpURL, scopesSupported }));
app.get('/demo/bootstrap', (_req, res) => res.json(tokens));

const authenticated = requireBearerAuth({ verifier, resourceMetadataUrl });
const scopeGates: Array<[string, express.RequestHandler]> = Object.entries(toolScopes).map(([name, scope]) => [
  name,
  requireBearerAuth({ verifier, requiredScopes: [scope], resourceMetadataUrl })
]);
// A tools/call for a scope-gated tool goes through that tool's gate, so the
// SDK answers a token without the scope with 403 insufficient_scope. The
// gate is found by comparing names, never by using the request's tool name
// as a key, so the request can only pick one of these handlers.
const gate: express.RequestHandler = (req, res, next) => {
  const body = req.body;
  const tool = body?.method === 'tools/call' ? body?.params?.name : undefined;
  let handler = authenticated;
  for (const [name, h] of scopeGates) {
    if (name === tool) handler = h;
  }
  handler(req, res, next);
};

const transports = new Map<string, StreamableHTTPServerTransport>();
app.all(mcpURL.pathname, gate, async (req, res) => {
  const sid = req.header('mcp-session-id');
  let transport = sid ? transports.get(sid) : undefined;
  if (!transport) {
    if (sid || req.method !== 'POST' || !isInitializeRequest(req.body)) {
      res.status(400).json({ jsonrpc: '2.0', error: { code: -32000, message: 'no session; send initialize first' }, id: null });
      return;
    }
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => {
        transports.set(id, transport!);
      }
    });
    transport.onclose = () => {
      if (transport!.sessionId) transports.delete(transport!.sessionId);
    };
    await newServer().connect(transport);
  }
  await transport.handleRequest(req, res, req.body);
});

app.listen(port, () => console.log(`TS SDK MCP fixture on ${mcpURL.href}, AS ${asURL}`));
