#!/usr/bin/env node
/**
 * Moeba Channel for Claude Code
 *
 * Two-way bridge: Moeba app users ↔ Claude Code session.
 * Authenticates via OAuth on startup, connects via SSE, replies via HTTP.
 *
 * Usage:
 *   npx @moeba/claude-channel
 *
 * On first run, opens browser for Google/Apple sign-in before connecting.
 * Credentials are cached per project at ~/.moeba/channel-<project>.json
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { createServer } from 'http';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';
import { execSync, exec } from 'child_process';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const MOEBA_API_URL = (
  process.env.MOEBA_API_URL ||
  'https://moeba-api-999642860678.africa-south1.run.app'
).replace(/\/$/, '');

const MOEBA_AUTH_URL =
  process.env.MOEBA_AUTH_URL || 'https://admin.moeba.co.za';

// Detect project name from git repo or directory name
function detectProjectName(): string {
  try {
    const repoName = execSync('git rev-parse --show-toplevel', {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
    return repoName.split('/').pop() || 'default';
  } catch {
    return process.cwd().split('/').pop() || 'default';
  }
}

const PROJECT_NAME = process.env.MOEBA_PROJECT || detectProjectName();
const PROJECT_SLUG = PROJECT_NAME.toLowerCase().replace(/[^a-z0-9]+/g, '-');
const CREDENTIALS_PATH = join(homedir(), '.moeba', `channel-${PROJECT_SLUG}.json`);

interface Credentials {
  token: string;
  email: string;
  businessId: string;
  agentId: string;
  connectionId: string;
  agentApiKey: string;
  projectName: string;
}

// ---------------------------------------------------------------------------
// Credential storage
// ---------------------------------------------------------------------------
function loadCredentials(): Credentials | null {
  try {
    if (!existsSync(CREDENTIALS_PATH)) return null;
    return JSON.parse(readFileSync(CREDENTIALS_PATH, 'utf-8'));
  } catch {
    return null;
  }
}

function saveCredentials(c: Credentials): void {
  const dir = join(homedir(), '.moeba');
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(CREDENTIALS_PATH, JSON.stringify(c, null, 2));
}

// Module-level credentials so the SSE loop and tool handlers always read the
// freshest token after a refresh.
let creds: Credentials | null = null;

// ---------------------------------------------------------------------------
// Session token (JWT) expiry — the session token is short-lived (~30 days),
// so we refresh it proactively rather than wedging on a dead token.
// ---------------------------------------------------------------------------
function decodeJwtExp(token: string): number | null {
  try {
    const part = token.split('.')[1];
    if (!part) return null;
    const json = Buffer.from(
      part.replace(/-/g, '+').replace(/_/g, '/'),
      'base64',
    ).toString('utf-8');
    const payload = JSON.parse(json);
    return typeof payload.exp === 'number' ? payload.exp : null;
  } catch {
    return null;
  }
}

// True when the token expires within `skewSeconds`. Returns false if the token
// has no decodable exp — in that case we let the server be the judge (the SSE
// 401 handler is the backstop) rather than forcing a refresh on every connect.
function isTokenExpired(token: string, skewSeconds = 300): boolean {
  const exp = decodeJwtExp(token);
  if (exp === null) return false;
  return Date.now() / 1000 >= exp - skewSeconds;
}

// ---------------------------------------------------------------------------
// OAuth flow — opens browser, receives Firebase token via localhost callback
// ---------------------------------------------------------------------------
function authenticate(): Promise<Credentials> {
  return new Promise((resolve, reject) => {
    const callbackPort = 9876;

    const httpServer = createServer(async (req, res) => {
      const url = new URL(req.url!, `http://localhost:${callbackPort}`);

      if (url.pathname === '/callback') {
        const firebaseIdToken = url.searchParams.get('token');

        if (!firebaseIdToken) {
          res.writeHead(400);
          res.end('Missing token parameter');
          return;
        }

        try {
          const response = await fetch(`${MOEBA_API_URL}/channel/auth`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ firebaseIdToken, projectName: PROJECT_NAME }),
          });

          if (!response.ok) {
            const err = await response.text();
            res.writeHead(500);
            res.end(`Auth failed: ${err}`);
            reject(new Error(`Channel auth failed: ${err}`));
            return;
          }

          const data = (await response.json()) as any;
          const newCreds: Credentials = {
            token: data.token,
            email: data.email,
            businessId: data.businessId,
            agentId: data.agentId,
            connectionId: data.connectionId,
            // The server only returns the agent key when it mints a new one (it
      // stores only the hash) — keep the known-good key instead of nulling it.
      agentApiKey: data.agentApiKey ?? creds?.agentApiKey ?? null,
            projectName: PROJECT_NAME,
          };

          saveCredentials(newCreds);

          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <html><body style="font-family:system-ui;text-align:center;padding:60px">
              <h2>Connected to Moeba!</h2>
              <p>You can close this tab and return to Claude Code.</p>
            </body></html>
          `);

          httpServer.close();
          resolve(newCreds);
        } catch (err: any) {
          res.writeHead(500);
          res.end(`Error: ${err.message}`);
          reject(err);
        }
        return;
      }

      res.writeHead(404);
      res.end('Not found');
    });

    httpServer.listen(callbackPort, '127.0.0.1', () => {
      const authUrl = `${MOEBA_AUTH_URL}/channel-login?redirect=http://localhost:${callbackPort}/callback`;
      console.error(`\n🔑 Sign in to Moeba: ${authUrl}\n`);

      const cmd =
        process.platform === 'darwin'
          ? 'open'
          : process.platform === 'win32'
            ? 'start'
            : 'xdg-open';
      exec(`${cmd} "${authUrl}"`);
    });

    setTimeout(() => {
      httpServer.close();
      reject(new Error('Authentication timed out after 2 minutes'));
    }, 120_000);
  });
}

// ---------------------------------------------------------------------------
// Headless auth — API key + email (no browser). Used for first-run headless
// setup and for unattended token refresh once the session token expires.
// ---------------------------------------------------------------------------
async function authenticateViaApiKey(
  apiKey: string,
  email: string,
): Promise<Credentials | null> {
  try {
    const response = await fetch(`${MOEBA_API_URL}/channel/auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKey, email, projectName: PROJECT_NAME }),
    });
    if (!response.ok) {
      console.error(`API key auth failed: ${await response.text()}`);
      return null;
    }
    const data = (await response.json()) as any;
    const newCreds: Credentials = {
      token: data.token,
      email: data.email,
      businessId: data.businessId,
      agentId: data.agentId,
      connectionId: data.connectionId,
      // The server only returns the agent key when it mints a new one (it
      // stores only the hash) — keep the known-good key instead of nulling it.
      agentApiKey: data.agentApiKey ?? creds?.agentApiKey ?? null,
      projectName: PROJECT_NAME,
    };
    saveCredentials(newCreds);
    return newCreds;
  } catch (err: any) {
    console.error(`API key auth error: ${err.message}`);
    return null;
  }
}

// Re-mint the short-lived session token when it expires. The agent API key
// stored alongside it is long-lived and re-mints a token unattended, so a
// configured channel self-heals with no user login, env vars, or browser.
// Order: stored agent key → env API key (first-run) → browser OAuth.
async function refreshCredentials(opts: {
  allowBrowser: boolean;
}): Promise<Credentials | null> {
  // 1. Best path: the already-stored agent key is non-expiring and works
  //    unattended inside the SSE reconnect loop.
  if (creds?.agentApiKey && creds?.email) {
    console.error('Refreshing Moeba session token via stored agent key...');
    const refreshed = await authenticateViaApiKey(creds.agentApiKey, creds.email);
    if (refreshed) return refreshed;
  }

  // 2. Headless env credentials (e.g. first run before anything is cached).
  const envApiKey = process.env.MOEBA_API_KEY;
  const envEmail = process.env.MOEBA_EMAIL;
  if (envApiKey && envEmail) {
    console.error('Refreshing Moeba session token via API key...');
    const refreshed = await authenticateViaApiKey(envApiKey, envEmail);
    if (refreshed) return refreshed;
  }

  // 3. Last resort: interactive browser OAuth.
  if (opts.allowBrowser) {
    console.error('Refreshing Moeba session token — opening browser...');
    try {
      return await authenticate();
    } catch (err: any) {
      console.error(`Re-authentication failed: ${err.message}`);
      return null;
    }
  }

  console.error(
    'Moeba session token expired and cannot refresh — reconnect with --login or set MOEBA_API_KEY + MOEBA_EMAIL.',
  );
  return null;
}

// ---------------------------------------------------------------------------
// SSE client — connects to Moeba and receives messages
// ---------------------------------------------------------------------------
function connectSSE(mcp: Server): void {
  let reconnectDelay = 1000;

  async function connect() {
    if (!creds) {
      console.error('Moeba SSE: no credentials — not connecting.');
      return;
    }
    try {
      // Proactively refresh a token that's expired/near-expiry so we don't
      // burn a guaranteed-401 connect attempt.
      if (isTokenExpired(creds.token)) {
        const refreshed = await refreshCredentials({ allowBrowser: false });
        if (refreshed) creds = refreshed;
      }

      const c = creds!; // snapshot for the life of this connection
      const url = `${MOEBA_API_URL}/api/channel/events?connectionId=${c.connectionId}`;
      console.error('Connecting to Moeba SSE...');
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${c.token}` },
      });

      if (!response.ok) {
        console.error(`SSE connection failed: ${response.status}`);
        // 401/403 → the session token was rejected. Re-authenticate (headless
        // only — we're past startup with no TTY) and reconnect promptly.
        if (response.status === 401 || response.status === 403) {
          const refreshed = await refreshCredentials({ allowBrowser: false });
          if (refreshed) {
            creds = refreshed;
            reconnectDelay = 1000;
          }
        }
        scheduleReconnect();
        return;
      }

      console.error('Connected to Moeba — listening for messages');
      reconnectDelay = 1000;

      const reader = response.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });

        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        let eventType = '';
        let eventData = '';

        for (const line of lines) {
          if (line.startsWith('event: ')) {
            eventType = line.slice(7);
          } else if (line.startsWith('data: ')) {
            eventData = line.slice(6);
          } else if (line === '' && eventType && eventData) {
            if (eventType === 'message') {
              try {
                const event = JSON.parse(eventData);
                const connId = event.connectionId || c.connectionId;
                const content = event.message?.text || '';
                const meta: Record<string, string> = {
                  sender_email: event.senderEmail || '',
                  sender_name: event.senderName || '',
                  connection_id: connId,
                  conversation_id: event.conversationId || '',
                };
                if (event.type === 'action') {
                  meta.type = 'action';
                }

                // Show progress indicator immediately so user sees typing
                fetch(`${MOEBA_API_URL}/api/agent/send`, {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                    'X-Moeba-Agent-Key': c.agentApiKey,
                  },
                  body: JSON.stringify({
                    connectionId: connId,
                    message: { text: 'Working on it...' },
                    type: 'progress',
                  }),
                }).catch(() => {});

                mcp
                  .notification({
                    method: 'notifications/claude/channel',
                    params: { content, meta },
                  })
                  .catch((err: any) =>
                    console.error('Notification failed:', err.message),
                  );
              } catch {}
            } else if (eventType === 'connected') {
              console.error('SSE stream established');
            }
            eventType = '';
            eventData = '';
          }
        }
      }

      console.error('SSE stream ended');
      scheduleReconnect();
    } catch (err: any) {
      console.error(`SSE error: ${err.message}`);
      scheduleReconnect();
    }
  }

  function scheduleReconnect() {
    console.error(`Reconnecting in ${reconnectDelay / 1000}s...`);
    setTimeout(connect, reconnectDelay);
    reconnectDelay = Math.min(reconnectDelay * 2, 30_000);
  }

  connect();
}

// ---------------------------------------------------------------------------
// Main — authenticate first, then connect MCP
// ---------------------------------------------------------------------------
async function main() {
  // 1. Authenticate — three modes:
  //    a. Cached credentials (fastest, no network)
  //    b. API key + email env vars (headless — SSH, CI, inviting others)
  //    c. Browser OAuth (--login flag)
  const loginMode = process.argv.includes('--login');
  const envApiKey = process.env.MOEBA_API_KEY;
  const envEmail = process.env.MOEBA_EMAIL;

  creds = loadCredentials();

  if (!creds && envApiKey && envEmail) {
    // Mode B: headless auth via API key + email
    console.error(`Authenticating as ${envEmail} via API key...`);
    creds = await authenticateViaApiKey(envApiKey, envEmail);
  } else if (!creds && loginMode) {
    // Mode C: browser OAuth
    console.error('No Moeba credentials found — opening browser to sign in...');
    creds = await authenticate();
  }

  // Refresh an expired/near-expiry cached token so we never connect with a
  // dead JWT (the bug that silently killed message delivery + notifications).
  if (creds && isTokenExpired(creds.token)) {
    console.error('Cached Moeba session token is expired or near expiry — refreshing...');
    const refreshed = await refreshCredentials({ allowBrowser: loginMode });
    if (refreshed) creds = refreshed;
  }

  if (creds) {
    console.error(`Authenticated as ${creds.email} (project: ${PROJECT_NAME})`);
  } else {
    console.error(`Moeba channel: no credentials for project "${PROJECT_NAME}" — run with --login or set MOEBA_API_KEY + MOEBA_EMAIL`);
  }

  // 2. Create MCP channel server
  const mcp = new Server(
    { name: 'moeba', version: '0.0.1' },
    {
      capabilities: {
        experimental: { 'claude/channel': {} },
        tools: {},
      },
      instructions: `Messages from Moeba users arrive as <channel source="moeba" ...>.
Each message has attributes: sender_email, sender_name, connection_id, conversation_id.

When you receive a message:
1. Read and understand the user's request
2. Take whatever actions are needed (read files, run commands, etc.)
3. Send progress updates via moeba_progress while working on longer tasks
4. Reply using moeba_reply with the connection_id from the message tag

IMPORTANT: The user is on a mobile app and CANNOT approve terminal permissions.
- Prefer reading files (Read tool) over running commands (Bash) when possible
- Use Glob, Grep, and Read tools which don't need permission
- If you must run a command, warn the user it needs terminal approval
- NEVER get stuck silently — if something needs approval, send a moeba_reply explaining that the action requires terminal approval
- Keep replies concise — the user is on a small screen`,
    },
  );

  // 3. Register tools
  mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'moeba_reply',
        description: 'Send a reply message back to the Moeba user',
        inputSchema: {
          type: 'object' as const,
          properties: {
            connection_id: {
              type: 'string',
              description: 'The connection_id from the inbound <channel> tag',
            },
            text: {
              type: 'string',
              description: 'The message to send back',
            },
          },
          required: ['connection_id', 'text'],
        },
      },
      {
        name: 'moeba_progress',
        description: 'Show a typing/progress indicator while working on a task',
        inputSchema: {
          type: 'object' as const,
          properties: {
            connection_id: {
              type: 'string',
              description: 'The connection_id from the inbound <channel> tag',
            },
            text: {
              type: 'string',
              description: 'Progress text (e.g. "Reading files...")',
            },
          },
          required: ['connection_id', 'text'],
        },
      },
    ],
  }));

  mcp.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args } = req.params;

    if (name === 'moeba_reply' || name === 'moeba_progress') {
      const { connection_id, text } = args as {
        connection_id: string;
        text: string;
      };

      const body: any = {
        connectionId: connection_id,
        message: { text },
      };
      if (name === 'moeba_progress') {
        body.type = 'progress';
      }

      const response = await fetch(`${MOEBA_API_URL}/api/agent/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Moeba-Agent-Key': creds!.agentApiKey,
        },
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        const errText = await response.text();
        return {
          content: [
            {
              type: 'text' as const,
              text: `Failed: ${response.status} ${errText}`,
            },
          ],
          isError: true,
        };
      }

      return {
        content: [
          {
            type: 'text' as const,
            text: name === 'moeba_progress' ? 'Progress updated' : 'Sent',
          },
        ],
      };
    }

    throw new Error(`Unknown tool: ${name}`);
  });

  // 4. Connect MCP to Claude Code
  await mcp.connect(new StdioServerTransport());

  // 5. Start SSE listener (only if authenticated)
  if (creds) {
    connectSSE(mcp);
    console.error('Moeba channel ready — waiting for messages');
  }
}

main().catch((err) => {
  console.error('Fatal:', err.message);
  process.exit(1);
});
