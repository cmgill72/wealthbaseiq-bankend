import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import {
  Configuration,
  PlaidApi,
  PlaidEnvironments,
  Products,
  CountryCode,
} from 'plaid';

const app = express();
app.use(express.json({ limit: '1mb' }));

const env = (process.env.PLAID_ENV ?? 'sandbox').toLowerCase();
const connectionLimit = Math.max(1, Number(process.env.PLAID_CONNECTION_LIMIT ?? 10));
const plaidConfigured = Boolean(process.env.PLAID_CLIENT_ID && process.env.PLAID_SECRET);
const apiKey = process.env.WEALTHBASEIQ_API_KEY ?? '';
const encryptionSecret = process.env.DATA_ENCRYPTION_KEY ?? '';
const storePath = path.resolve(process.env.DATA_STORE_PATH ?? './data/store.enc');
const syncMinutes = Math.max(15, Number(process.env.BACKGROUND_SYNC_MINUTES ?? 60));
const basePath = env === 'production'
  ? PlaidEnvironments.production
  : env === 'development'
    ? PlaidEnvironments.development
    : PlaidEnvironments.sandbox;

const plaid = new PlaidApi(new Configuration({
  basePath,
  baseOptions: {
    headers: {
      'PLAID-CLIENT-ID': process.env.PLAID_CLIENT_ID ?? '',
      'PLAID-SECRET': process.env.PLAID_SECRET ?? '',
    },
  },
}));

type Owner = 'Christopher' | 'Wife' | 'Joint';
type ConnectionType = 'Investment' | 'Banking';
type ConnectionStatus = 'connected' | 'needs attention' | 'testing' | 'disconnected';

type NetWorthPoint = { date: string; total: number; investments: number; cash: number };
type ConnectedItem = {
  owner: Owner;
  connectionType: ConnectionType;
  accessToken: string;
  itemID: string;
  institutionName?: string;
  lastUpdated?: string;
  lastSuccessfulSync?: string;
  lastTested?: string;
  lastError?: string | null;
  status?: ConnectionStatus;
};
type CachedSnapshot = { accounts: any[]; holdings: any[]; generatedAt: string };
type PersistedStore = {
  version: 1;
  items: ConnectedItem[];
  history: NetWorthPoint[];
  cachedSnapshot?: CachedSnapshot;
  webhookEvents?: Array<{ receivedAt: string; webhookType?: string; webhookCode?: string; itemID?: string }>;
};

let store: PersistedStore = { version: 1, items: [], history: [], webhookEvents: [] };
let syncInProgress = false;

function environmentLabel() {
  if (env === 'production') return 'Production / Live';
  if (env === 'development') return 'Development / Trial';
  return 'Sandbox';
}

function keyBytes(): Buffer {
  // Accept any passphrase and derive a fixed-size key. In production use a long random secret.
  return crypto.createHash('sha256').update(encryptionSecret || 'WEALTHBASEIQ-LOCAL-DEV-ONLY').digest();
}

function encryptStore(data: PersistedStore): Buffer {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBytes(), iv);
  const plaintext = Buffer.from(JSON.stringify(data), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from('WBIQ1'), iv, tag, encrypted]);
}

function decryptStore(buffer: Buffer): PersistedStore {
  const header = buffer.subarray(0, 5).toString('utf8');
  if (header !== 'WBIQ1') throw new Error('Unsupported WealthBaseIQ store format.');
  const iv = buffer.subarray(5, 17);
  const tag = buffer.subarray(17, 33);
  const encrypted = buffer.subarray(33);
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBytes(), iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

function loadStore() {
  try {
    if (!fs.existsSync(storePath)) return;
    store = decryptStore(fs.readFileSync(storePath));
    store.items ??= [];
    store.history ??= [];
    store.webhookEvents ??= [];
  } catch (error: any) {
    console.error('Persistent store could not be loaded:', error?.message ?? error);
    console.error('The server will not overwrite it until a successful write is requested. Check DATA_ENCRYPTION_KEY.');
  }
}

function saveStore() {
  fs.mkdirSync(path.dirname(storePath), { recursive: true });
  const temp = `${storePath}.tmp`;
  fs.writeFileSync(temp, encryptStore(store), { mode: 0o600 });
  fs.renameSync(temp, storePath);
}

loadStore();

function requireAPIKey(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (!apiKey) {
    if (env === 'production') return res.status(503).json({ error: { message: 'Backend authentication is not configured.', error_code: 'API_AUTH_NOT_CONFIGURED' } });
    return next();
  }
  const supplied = req.header('x-wealthbaseiq-key') ?? req.header('authorization')?.replace(/^Bearer\s+/i, '');
  if (supplied !== apiKey) return res.status(401).json({ error: { message: 'Unauthorized.', error_code: 'UNAUTHORIZED' } });
  next();
}

// Health remains public for deployment diagnostics. All financial API routes below are authenticated.
app.use('/api', (req, res, next) => req.path === '/health' || req.path === '/plaid/webhook' ? next() : requireAPIKey(req, res, next));

function structuredError(error: any) {
  const rawError = error?.response?.data;
  const plaidError = rawError?.error ?? rawError;
  if (plaidError) {
    return {
      message: plaidError.display_message ?? plaidError.error_message ?? 'Plaid request failed.',
      display_message: plaidError.display_message ?? null,
      error_code: plaidError.error_code ?? null,
      error_type: plaidError.error_type ?? null,
      request_id: plaidError.request_id ?? null,
    };
  }
  return { message: error?.message ?? String(error), display_message: null, error_code: null, error_type: null, request_id: null };
}

function fail(res: express.Response, error: any, status = 500) { res.status(error?.status ?? status).json({ error: structuredError(error) }); }
function localError(message: string, code: string, status: number) {
  return { status, payload: { error: { message, display_message: message, error_code: code, error_type: 'WEALTHBASEIQ', request_id: null } } };
}

function recordHistory(accounts: any[]) {
  const total = accounts.reduce((sum, a) => sum + Number(a.currentBalance ?? 0), 0);
  const investments = accounts.filter(a => a.kind === 'investment').reduce((sum, a) => sum + Number(a.currentBalance ?? 0), 0);
  const cash = accounts.filter(a => a.kind === 'checking' || a.kind === 'savings').reduce((sum, a) => sum + Number(a.currentBalance ?? 0), 0);
  const point = { date: new Date().toISOString(), total, investments, cash };
  const today = point.date.slice(0, 10);
  const index = store.history.findIndex(entry => entry.date.slice(0, 10) === today);
  if (index >= 0) store.history[index] = point; else store.history.push(point);
  store.history.sort((a, b) => a.date.localeCompare(b.date));
}

async function resolveInstitution(item: ConnectedItem): Promise<string> {
  if (item.institutionName) return item.institutionName;
  try {
    const itemResponse = await plaid.itemGet({ access_token: item.accessToken });
    const institutionID = itemResponse.data.item.institution_id;
    if (!institutionID) return 'Connected Institution';
    const institution = await plaid.institutionsGetById({ institution_id: institutionID, country_codes: [CountryCode.Us] });
    item.institutionName = institution.data.institution.name;
    return item.institutionName ?? 'Connected Institution';
  } catch { return 'Connected Institution'; }
}

async function evaluateItem(item: ConnectedItem) {
  try {
    const response = await plaid.itemGet({ access_token: item.accessToken });
    const plaidError: any = response.data.item.error;
    item.status = plaidError ? 'needs attention' : 'connected';
    item.lastError = plaidError?.display_message ?? plaidError?.error_message ?? null;
  } catch (error: any) {
    item.status = 'needs attention';
    item.lastError = structuredError(error).message;
  }
}

async function buildSnapshot(): Promise<CachedSnapshot> {
  if (syncInProgress && store.cachedSnapshot) return store.cachedSnapshot;
  syncInProgress = true;
  try {
    const accounts: any[] = [];
    const holdings: any[] = [];
    for (const item of store.items) {
      const institution = await resolveInstitution(item);
      try {
        const accountResponse = await plaid.accountsGet({ access_token: item.accessToken });
        for (const account of accountResponse.data.accounts) {
          const accountType = String(account.type);
          const subtype = String(account.subtype ?? '');
          let kind = 'other';
          if (accountType === 'investment') kind = 'investment';
          else if (subtype === 'checking') kind = 'checking';
          else if (subtype === 'savings' || subtype === 'money market') kind = 'savings';
          accounts.push({
            id: account.account_id, institution, name: account.name, mask: account.mask ?? null,
            owner: item.owner, kind, currentBalance: account.balances.current ?? 0,
            availableBalance: account.balances.available ?? null, lastUpdated: new Date().toISOString(),
          });
        }
        if (item.connectionType === 'Investment') {
          try {
            const inv = await plaid.investmentsHoldingsGet({ access_token: item.accessToken });
            const securities = new Map(inv.data.securities.map(security => [security.security_id, security]));
            for (const holding of inv.data.holdings) {
              const security: any = securities.get(holding.security_id);
              holdings.push({
                id: `${holding.account_id}-${holding.security_id}`, accountID: holding.account_id,
                name: security?.name ?? 'Security', ticker: security?.ticker_symbol ?? null,
                securityType: String(security?.type ?? 'other'), quantity: holding.quantity ?? 0,
                price: holding.institution_price ?? 0, value: holding.institution_value ?? 0,
                costBasis: holding.cost_basis ?? null,
              });
            }
          } catch (error: any) {
            item.lastError = `Holdings: ${structuredError(error).message}`;
          }
        }
        item.lastUpdated = new Date().toISOString();
        item.lastSuccessfulSync = item.lastUpdated;
        item.status = 'connected';
        if (!item.lastError?.startsWith('Holdings:')) item.lastError = null;
      } catch (error: any) {
        item.status = 'needs attention';
        item.lastError = structuredError(error).message;
      }
    }
    const snapshot = { accounts, holdings, generatedAt: new Date().toISOString() };
    if (accounts.length > 0) {
      recordHistory(accounts);
      store.cachedSnapshot = snapshot;
      saveStore();
      return snapshot;
    }

    saveStore();
    if (store.items.length > 0) {
      const issue = localError('Connected Items exist, but no account data could be read. Existing cached data should be used instead of displaying zero balances.', 'NO_READABLE_ACCOUNTS', 503);
      throw Object.assign(new Error(issue.payload.error.message), { status: issue.status, response: { data: issue.payload } });
    }
    return snapshot;
  } finally { syncInProgress = false; }
}

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true, environment: env, environmentLabel: environmentLabel(), connectedItems: store.items.length,
    connectionLimit, remainingConnections: Math.max(connectionLimit - store.items.length, 0), plaidConfigured,
    redirectURIConfigured: Boolean(process.env.PLAID_REDIRECT_URI), webhookConfigured: Boolean(process.env.PLAID_WEBHOOK_URL),
    persistentStoreEnabled: true, encryptedStoreConfigured: Boolean(encryptionSecret), apiAuthConfigured: Boolean(apiKey),
    cachedSnapshotAvailable: Boolean(store.cachedSnapshot), lastSnapshotAt: store.cachedSnapshot?.generatedAt ?? null,
    backgroundSyncMinutes: syncMinutes,
  });
});

app.post('/api/plaid/link-token', async (req, res) => {
  try {
    if (!plaidConfigured) { const issue = localError('Plaid credentials are missing from the backend .env file.', 'PLAID_NOT_CONFIGURED', 503); return res.status(issue.status).json(issue.payload); }
    if (store.items.length >= connectionLimit) { const issue = localError(`The configured Plaid trial connection limit of ${connectionLimit} has been reached.`, 'TRIAL_CONNECTION_LIMIT', 409); return res.status(issue.status).json(issue.payload); }
    const owner = req.body?.owner as Owner | undefined;
    const connectionType = req.body?.connectionType as ConnectionType | undefined;
    if (!owner || !connectionType) { const issue = localError('owner and connectionType are required.', 'INVALID_CONNECTION_REQUEST', 400); return res.status(issue.status).json(issue.payload); }
    const request: any = {
      user: { client_user_id: `wealthbaseiq-${owner.toLowerCase()}` }, client_name: 'WealthBaseIQ',
      products: connectionType === 'Investment' ? [Products.Investments] : [Products.Transactions],
      country_codes: [CountryCode.Us], language: 'en',
    };
    if (process.env.PLAID_REDIRECT_URI) request.redirect_uri = process.env.PLAID_REDIRECT_URI;
    if (process.env.PLAID_WEBHOOK_URL) request.webhook = process.env.PLAID_WEBHOOK_URL;
    const response = await plaid.linkTokenCreate(request);
    res.json({ linkToken: response.data.link_token });
  } catch (error: any) { fail(res, error); }
});

app.post('/api/plaid/update-link-token', async (req, res) => {
  try {
    const item = store.items.find(i => i.itemID === req.body?.itemID);
    if (!item) { const issue = localError('Connection not found.', 'CONNECTION_NOT_FOUND', 404); return res.status(issue.status).json(issue.payload); }
    const request: any = { user: { client_user_id: `wealthbaseiq-${item.owner.toLowerCase()}` }, client_name: 'WealthBaseIQ', country_codes: [CountryCode.Us], language: 'en', access_token: item.accessToken };
    if (process.env.PLAID_REDIRECT_URI) request.redirect_uri = process.env.PLAID_REDIRECT_URI;
    if (process.env.PLAID_WEBHOOK_URL) request.webhook = process.env.PLAID_WEBHOOK_URL;
    const response = await plaid.linkTokenCreate(request);
    res.json({ linkToken: response.data.link_token });
  } catch (error: any) { fail(res, error); }
});

app.post('/api/plaid/exchange', async (req, res) => {
  try {
    if (store.items.length >= connectionLimit) { const issue = localError(`The configured Plaid trial connection limit of ${connectionLimit} has been reached.`, 'TRIAL_CONNECTION_LIMIT', 409); return res.status(issue.status).json(issue.payload); }
    const { publicToken, owner, connectionType } = req.body as { publicToken?: string; owner?: Owner; connectionType?: ConnectionType };
    if (!publicToken || !owner || !connectionType) { const issue = localError('publicToken, owner and connectionType are required.', 'INVALID_EXCHANGE_REQUEST', 400); return res.status(issue.status).json(issue.payload); }
    const response = await plaid.itemPublicTokenExchange({ public_token: publicToken });
    const connected: ConnectedItem = { owner, connectionType, accessToken: response.data.access_token, itemID: response.data.item_id, lastUpdated: new Date().toISOString(), status: 'connected', lastError: null };
    await resolveInstitution(connected);
    const duplicate = store.items.find(item => item.owner === owner && item.connectionType === connectionType && item.institutionName === connected.institutionName);
    if (duplicate) {
      try { await plaid.itemRemove({ access_token: connected.accessToken }); } catch { /* best effort */ }
      const issue = localError(`${connected.institutionName ?? 'This institution'} is already connected for ${owner} as a ${connectionType.toLowerCase()} connection.`, 'DUPLICATE_CONNECTION', 409);
      return res.status(issue.status).json(issue.payload);
    }
    store.items.push(connected); saveStore();
    res.json({ ok: true, itemID: connected.itemID, institution: connected.institutionName, connectedItems: store.items.length, remainingConnections: Math.max(connectionLimit - store.items.length, 0) });
  } catch (error: any) { fail(res, error); }
});

app.get('/api/connections', async (_req, res) => {
  try {
    await Promise.all(store.items.map(evaluateItem)); saveStore();
    res.json(await Promise.all(store.items.map(async item => ({
      id: item.itemID, owner: item.owner, institution: await resolveInstitution(item), connectionType: item.connectionType,
      status: item.status ?? 'connected', lastUpdated: item.lastUpdated ?? null, lastSuccessfulSync: item.lastSuccessfulSync ?? null,
      lastTested: item.lastTested ?? null, lastError: item.lastError ?? null, trialSlotUsed: true,
    }))));
  } catch (error: any) { fail(res, error); }
});

app.post('/api/connections/:itemID/test', async (req, res) => {
  const item = store.items.find(i => i.itemID === req.params.itemID);
  if (!item) { const issue = localError('Connection not found.', 'CONNECTION_NOT_FOUND', 404); return res.status(issue.status).json(issue.payload); }
  const started = Date.now();
  item.status = 'testing';
  try {
    const accountResponse = await plaid.accountsGet({ access_token: item.accessToken });
    let holdingsReadable: boolean | null = null;
    if (item.connectionType === 'Investment') {
      try { await plaid.investmentsHoldingsGet({ access_token: item.accessToken }); holdingsReadable = true; } catch { holdingsReadable = false; }
    }
    item.lastTested = new Date().toISOString(); item.status = 'connected'; item.lastError = null; saveStore();
    res.json({ ok: true, status: 'connected', latencyMS: Date.now() - started, accountCount: accountResponse.data.accounts.length, holdingsReadable, testedAt: item.lastTested });
  } catch (error: any) {
    const detail = structuredError(error); item.lastTested = new Date().toISOString(); item.status = 'needs attention'; item.lastError = detail.message; saveStore();
    res.status(502).json({ error: detail, test: { ok: false, status: item.status, latencyMS: Date.now() - started, testedAt: item.lastTested } });
  }
});

app.delete('/api/connections/:itemID', async (req, res) => {
  const index = store.items.findIndex(i => i.itemID === req.params.itemID);
  if (index < 0) { const issue = localError('Connection not found.', 'CONNECTION_NOT_FOUND', 404); return res.status(issue.status).json(issue.payload); }
  const [item] = store.items.splice(index, 1);
  try { await plaid.itemRemove({ access_token: item.accessToken }); } catch { /* remote item may already be invalid */ }
  if (store.items.length === 0) {
    store.cachedSnapshot = undefined;
    store.history = [];
  }
  saveStore();
  res.json({ ok: true, connectedItems: store.items.length, remainingConnections: Math.max(connectionLimit - store.items.length, 0) });
});

app.get('/api/history', (_req, res) => res.json(store.history));
app.get('/api/snapshot/cached', (_req, res) => store.cachedSnapshot ? res.json(store.cachedSnapshot) : res.status(404).json({ error: { message: 'No cached snapshot is available.', error_code: 'NO_CACHED_SNAPSHOT' } }));
app.get('/api/snapshot', async (_req, res) => {
  try {
    if (store.items.length === 0) {
      return res.json({ accounts: [], holdings: [], generatedAt: new Date().toISOString() });
    }
    res.json(await buildSnapshot());
  } catch (error: any) { fail(res, error); }
});

app.delete('/api/data', async (_req, res) => {
  for (const item of store.items) { try { await plaid.itemRemove({ access_token: item.accessToken }); } catch { /* best effort */ } }
  store = { version: 1, items: [], history: [], webhookEvents: [] }; saveStore();
  res.json({ ok: true });
});

app.post('/api/plaid/webhook', async (req, res) => {
  const event = req.body ?? {};
  store.webhookEvents ??= [];
  store.webhookEvents.push({ receivedAt: new Date().toISOString(), webhookType: event.webhook_type, webhookCode: event.webhook_code, itemID: event.item_id });
  store.webhookEvents = store.webhookEvents.slice(-100);
  const item = store.items.find(i => i.itemID === event.item_id);
  if (item && event.error) { item.status = 'needs attention'; item.lastError = event.error.display_message ?? event.error.error_message ?? 'Plaid reported an Item error.'; }
  saveStore();
  res.sendStatus(200);
  if (item && ['HOLDINGS', 'TRANSACTIONS', 'ITEM'].includes(String(event.webhook_type ?? ''))) buildSnapshot().catch(() => undefined);
});

setInterval(() => {
  if (store.items.length > 0) buildSnapshot().catch(error => console.warn('Background sync failed:', structuredError(error).message));
}, syncMinutes * 60 * 1000);

app.listen(Number(process.env.PORT ?? 8080), () => {
  console.log(`WealthBaseIQ backend listening on port ${process.env.PORT ?? 8080} (${environmentLabel()})`);
  console.log(`Plaid configured: ${plaidConfigured ? 'yes' : 'no'} | connections: ${store.items.length}/${connectionLimit} | encrypted persistence: yes`);
  if (!apiKey) console.warn('WEALTHBASEIQ_API_KEY is not set. Development requests are unauthenticated; production will reject them.');
  if (!encryptionSecret) console.warn('DATA_ENCRYPTION_KEY is not set. A development-only fallback is active; set a strong secret before real financial data.');
});
