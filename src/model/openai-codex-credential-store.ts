import { decodeJwt } from "jose";
import { decryptSecret, deriveConnectorKey, encryptSecret } from "../connectors/connector-client-store.ts";
import type { AdvisoryLock } from "../persistence/advisory-lock.ts";
import type { DurableMap } from "../persistence/durable-map.ts";
import { createKeyedQueue } from "../util/async.ts";

export type OpenAICodexAuthPhase =
  | "absent"
  | "pending"
  | "slow_down"
  | "denied"
  | "expired"
  | "connected"
  | "reconnect_required";

export interface OpenAICodexPublicStatus {
  provider: "openai-codex";
  phase: OpenAICodexAuthPhase;
  configured: boolean;
  verificationUrl?: string;
  userCode?: string;
  intervalSeconds?: number;
  expiresAt?: number;
  updatedAt?: number;
  updatedBy?: string;
}

export interface OpenAICodexCredentialStore {
  startAuthorization(actorId: string): Promise<OpenAICodexPublicStatus>;
  getAuthorizationStatus(): Promise<OpenAICodexPublicStatus>;
  cancelAuthorization(actorId: string): Promise<OpenAICodexPublicStatus>;
  disconnect(actorId: string): Promise<OpenAICodexPublicStatus>;
  resolveAccessToken(): Promise<string | null>;
  isConfigured(): Promise<boolean>;
}

const PROVIDER = "openai-codex" as const;
const RECORD_KEY = "openai-codex";
const LOCK_KEY = "openai-codex-oauth";
const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const AUTH_BASE = "https://auth.openai.com";
const USERCODE_URL = `${AUTH_BASE}/api/accounts/deviceauth/usercode`;
const POLL_URL = `${AUTH_BASE}/api/accounts/deviceauth/token`;
const OAUTH_TOKEN_URL = `${AUTH_BASE}/oauth/token`;
const VERIFICATION_URL = `${AUTH_BASE}/codex/device`;
const REDIRECT_URI = `${AUTH_BASE}/deviceauth/callback`;
const DEVICE_TTL_MS = 15 * 60_000;
const MIN_INTERVAL_SEC = 3;
const ACCESS_SKEW_SEC = 120;
const SLOW_DOWN_BUMP_SEC = 5;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

interface PendingState {
  deviceAuthIdEnc: string;
  userCodeEnc: string;
  verificationUrl: string;
  intervalSeconds: number;
  expiresAt: number;
  nextPollAt: number;
  startedAt: number;
  startedBy: string;
}

interface CredentialState {
  accessTokenEnc: string;
  refreshTokenEnc: string;
  connectedAt: number;
  connectedBy: string;
}

interface ExchangePayload {
  authorizationCode: string;
  codeVerifier: string;
}

interface StoredOpenAICodexRecord {
  provider: typeof PROVIDER;
  phase: OpenAICodexAuthPhase;
  pending?: PendingState;
  exchangeEnc?: string;
  credential?: CredentialState;
  updatedAt: number;
  updatedBy: string;
}

type FetchLike = typeof fetch;

type ExchangeOutcome =
  | { kind: "connected"; accessToken: string; refreshToken: string }
  | { kind: "transient"; retryAfterSeconds: number }
  | { kind: "denied" };

export function createOpenAICodexCredentialStore(input: {
  backing: DurableMap<StoredOpenAICodexRecord>;
  keyMaterial: string | Buffer;
  fetch: FetchLike;
  advisoryLock: AdvisoryLock;
  now?: () => number;
  requestTimeoutMs?: number;
}): OpenAICodexCredentialStore {
  const key = deriveConnectorKey(input.keyMaterial, "openai-codex-credentials");
  const now = input.now ?? Date.now;
  const requestTimeoutMs = input.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  const mutationQueue = createKeyedQueue<string>();

  function withStoreLock<T>(fn: () => Promise<T>): Promise<T> {
    return mutationQueue(LOCK_KEY, () => input.advisoryLock.withLock(LOCK_KEY, fn));
  }

  function requestSignal(): AbortSignal {
    return AbortSignal.timeout(requestTimeoutMs);
  }

  async function load(): Promise<StoredOpenAICodexRecord | null> {
    return input.backing.get(RECORD_KEY);
  }

  async function save(record: StoredOpenAICodexRecord): Promise<void> {
    await input.backing.put(RECORD_KEY, record);
  }

  function hasLiveCredential(record: StoredOpenAICodexRecord | null): boolean {
    return !!record?.credential && record.phase !== "reconnect_required";
  }

  function toPublic(
    record: StoredOpenAICodexRecord | null,
    configuredOverride?: boolean,
  ): OpenAICodexPublicStatus {
    if (!record) {
      return { provider: PROVIDER, phase: "absent", configured: false };
    }
    const configured =
      configuredOverride !== undefined ? configuredOverride : hasLiveCredential(record);
    const status: OpenAICodexPublicStatus = {
      provider: PROVIDER,
      phase: record.phase,
      configured,
      updatedAt: record.updatedAt,
      updatedBy: record.updatedBy,
    };
    if (
      record.pending &&
      (record.phase === "pending" || record.phase === "slow_down")
    ) {
      status.verificationUrl = record.pending.verificationUrl;
      status.userCode = decryptSecret(record.pending.userCodeEnc, key);
      status.intervalSeconds = record.pending.intervalSeconds;
      status.expiresAt = record.pending.expiresAt;
    }
    return status;
  }

  function parseInterval(value: unknown): number {
    const raw =
      typeof value === "number"
        ? value
        : typeof value === "string"
          ? Number(value.trim())
          : Number.NaN;
    if (!Number.isFinite(raw) || raw <= 0) return MIN_INTERVAL_SEC;
    return Math.max(MIN_INTERVAL_SEC, Math.floor(raw));
  }

  function parseRetryAfter(res: Response, fallbackSeconds: number, t: number): number {
    const header = res.headers.get("retry-after");
    if (header) {
      const trimmed = header.trim();
      const asInt = Number(trimmed);
      if (Number.isFinite(asInt) && asInt > 0) return Math.max(MIN_INTERVAL_SEC, Math.floor(asInt));
      const asDate = Date.parse(trimmed);
      if (Number.isFinite(asDate)) {
        const deltaSec = Math.ceil((asDate - t) / 1000);
        return Math.max(MIN_INTERVAL_SEC, deltaSec > 0 ? deltaSec : MIN_INTERVAL_SEC);
      }
    }
    return Math.max(MIN_INTERVAL_SEC, fallbackSeconds);
  }

  function jwtExpSeconds(token: string): number | null {
    try {
      const claims = decodeJwt(token);
      return typeof claims.exp === "number" ? claims.exp : null;
    } catch {
      return null;
    }
  }

  function tokenStillFresh(token: string, t: number): boolean {
    const exp = jwtExpSeconds(token);
    if (exp === null) return false;
    return exp - Math.floor(t / 1000) > ACCESS_SKEW_SEC;
  }

  function tokenNotExpired(token: string, t: number): boolean {
    const exp = jwtExpSeconds(token);
    if (exp === null) return false;
    return exp > Math.floor(t / 1000);
  }

  async function readErrorCode(res: Response): Promise<string | null> {
    try {
      const text = await res.text();
      if (!text) return null;
      const parsed = JSON.parse(text) as { error?: unknown };
      if (typeof parsed.error === "string") return parsed.error;
      if (parsed.error && typeof parsed.error === "object") {
        const code = (parsed.error as { code?: unknown }).code;
        return typeof code === "string" ? code : null;
      }
      return null;
    } catch {
      return null;
    }
  }

  function isPendingError(errorCode: string | null): boolean {
    return errorCode === "authorization_pending" || errorCode === "deviceauth_authorization_pending";
  }

  function encryptExchange(payload: ExchangePayload): string {
    return encryptSecret(JSON.stringify(payload), key);
  }

  function decryptExchange(exchangeEnc: string): ExchangePayload | null {
    try {
      const parsed = JSON.parse(decryptSecret(exchangeEnc, key)) as {
        authorizationCode?: unknown;
        codeVerifier?: unknown;
      };
      if (
        typeof parsed.authorizationCode !== "string" ||
        !parsed.authorizationCode ||
        typeof parsed.codeVerifier !== "string" ||
        !parsed.codeVerifier
      ) {
        return null;
      }
      return {
        authorizationCode: parsed.authorizationCode,
        codeVerifier: parsed.codeVerifier,
      };
    } catch {
      return null;
    }
  }

  async function exchangeAuthorizationCode(
    authorizationCode: string,
    codeVerifier: string,
    fallbackIntervalSeconds: number,
    t: number,
  ): Promise<ExchangeOutcome> {
    let res: Response;
    try {
      res = await input.fetch(OAUTH_TOKEN_URL, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: authorizationCode,
          redirect_uri: REDIRECT_URI,
          client_id: CLIENT_ID,
          code_verifier: codeVerifier,
        }).toString(),
        signal: requestSignal(),
      });
    } catch {
      return { kind: "transient", retryAfterSeconds: Math.max(MIN_INTERVAL_SEC, fallbackIntervalSeconds) };
    }

    if (res.status === 429 || res.status >= 500) {
      return {
        kind: "transient",
        retryAfterSeconds: parseRetryAfter(res, fallbackIntervalSeconds, t),
      };
    }

    if (!res.ok) {
      return { kind: "denied" };
    }

    let raw: Record<string, unknown>;
    try {
      raw = (await res.json()) as Record<string, unknown>;
    } catch {
      return { kind: "denied" };
    }
    const accessToken = typeof raw.access_token === "string" ? raw.access_token : "";
    const refreshToken = typeof raw.refresh_token === "string" ? raw.refresh_token : "";
    if (!accessToken || !refreshToken) {
      return { kind: "denied" };
    }
    return { kind: "connected", accessToken, refreshToken };
  }

  async function completeExchange(
    record: StoredOpenAICodexRecord,
    payload: ExchangePayload,
  ): Promise<StoredOpenAICodexRecord> {
    const pending = record.pending;
    const t = now();
    const intervalSeconds = pending?.intervalSeconds ?? MIN_INTERVAL_SEC;
    const outcome = await exchangeAuthorizationCode(
      payload.authorizationCode,
      payload.codeVerifier,
      intervalSeconds,
      t,
    );

    if (outcome.kind === "connected") {
      const connected: StoredOpenAICodexRecord = {
        provider: PROVIDER,
        phase: "connected",
        credential: {
          accessTokenEnc: encryptSecret(outcome.accessToken, key),
          refreshTokenEnc: encryptSecret(outcome.refreshToken, key),
          connectedAt: t,
          connectedBy: pending?.startedBy ?? record.updatedBy,
        },
        updatedAt: t,
        updatedBy: pending?.startedBy ?? record.updatedBy,
      };
      await save(connected);
      return connected;
    }

    if (outcome.kind === "transient") {
      if (!pending) {
        const denied: StoredOpenAICodexRecord = {
          ...record,
          phase: "denied",
          pending: undefined,
          exchangeEnc: undefined,
          updatedAt: t,
        };
        await save(denied);
        return denied;
      }
      const retrying: StoredOpenAICodexRecord = {
        ...record,
        phase: record.phase === "slow_down" ? "slow_down" : "pending",
        pending: {
          ...pending,
          intervalSeconds: Math.max(pending.intervalSeconds, outcome.retryAfterSeconds),
          nextPollAt: t + outcome.retryAfterSeconds * 1000,
        },
        exchangeEnc: record.exchangeEnc ?? encryptExchange(payload),
        updatedAt: t,
      };
      await save(retrying);
      return retrying;
    }

    const denied: StoredOpenAICodexRecord = {
      ...record,
      phase: "denied",
      pending: undefined,
      exchangeEnc: undefined,
      updatedAt: t,
    };
    await save(denied);
    return denied;
  }

  async function pollOnce(record: StoredOpenAICodexRecord): Promise<StoredOpenAICodexRecord> {
    const pending = record.pending;
    if (!pending) return record;
    const t = now();
    if (t >= pending.expiresAt) {
      return {
        ...record,
        phase: "expired",
        pending: undefined,
        exchangeEnc: undefined,
        updatedAt: t,
        updatedBy: record.updatedBy,
      };
    }
    if (t < pending.nextPollAt) return record;

    const deviceAuthId = decryptSecret(pending.deviceAuthIdEnc, key);
    const userCode = decryptSecret(pending.userCodeEnc, key);

    let res: Response;
    try {
      res = await input.fetch(POLL_URL, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ device_auth_id: deviceAuthId, user_code: userCode }),
        signal: requestSignal(),
      });
    } catch {
      return {
        ...record,
        phase: record.phase === "slow_down" ? "slow_down" : "pending",
        pending: {
          ...pending,
          nextPollAt: t + pending.intervalSeconds * 1000,
        },
        updatedAt: t,
      };
    }

    if (res.ok) {
      let body: Record<string, unknown>;
      try {
        body = (await res.json()) as Record<string, unknown>;
      } catch {
        return {
          ...record,
          phase: "denied",
          pending: undefined,
          exchangeEnc: undefined,
          updatedAt: t,
        };
      }
      const authorizationCode = typeof body.authorization_code === "string" ? body.authorization_code : "";
      const codeVerifier = typeof body.code_verifier === "string" ? body.code_verifier : "";
      if (!authorizationCode || !codeVerifier) {
        return {
          ...record,
          phase: "denied",
          pending: undefined,
          exchangeEnc: undefined,
          updatedAt: t,
        };
      }
      const payload: ExchangePayload = { authorizationCode, codeVerifier };
      const withExchange: StoredOpenAICodexRecord = {
        ...record,
        exchangeEnc: encryptExchange(payload),
        updatedAt: t,
      };
      await save(withExchange);
      return completeExchange(withExchange, payload);
    }

    if (res.status === 410) {
      return {
        ...record,
        phase: "expired",
        pending: undefined,
        exchangeEnc: undefined,
        updatedAt: t,
      };
    }

    const errorCode = await readErrorCode(res);
    if (res.status === 429 || errorCode === "slow_down") {
      const intervalSeconds = parseRetryAfter(res, pending.intervalSeconds + SLOW_DOWN_BUMP_SEC, t);
      return {
        ...record,
        phase: "slow_down",
        pending: {
          ...pending,
          intervalSeconds,
          nextPollAt: t + intervalSeconds * 1000,
        },
        updatedAt: t,
      };
    }

    if (
      res.status === 403 ||
      res.status === 404 ||
      isPendingError(errorCode) ||
      res.status >= 500
    ) {
      return {
        ...record,
        phase: "pending",
        pending: {
          ...pending,
          nextPollAt: t + pending.intervalSeconds * 1000,
        },
        updatedAt: t,
      };
    }

    if (res.status >= 400 && res.status < 500) {
      return {
        ...record,
        phase: "denied",
        pending: undefined,
        exchangeEnc: undefined,
        updatedAt: t,
      };
    }

    return {
      ...record,
      phase: "pending",
      pending: {
        ...pending,
        nextPollAt: t + pending.intervalSeconds * 1000,
      },
      updatedAt: t,
    };
  }

  async function refreshTokens(
    record: StoredOpenAICodexRecord,
  ): Promise<{ accessToken: string | null; record: StoredOpenAICodexRecord }> {
    if (!record.credential) return { accessToken: null, record };
    const t = now();
    const accessToken = decryptSecret(record.credential.accessTokenEnc, key);
    const refreshToken = decryptSecret(record.credential.refreshTokenEnc, key);
    const snapshotConnectedAt = record.credential.connectedAt;

    let res: Response;
    try {
      res = await input.fetch(OAUTH_TOKEN_URL, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: CLIENT_ID,
        }).toString(),
        signal: requestSignal(),
      });
    } catch {
      return {
        accessToken: tokenNotExpired(accessToken, t) ? accessToken : null,
        record,
      };
    }

    const latest = await load();
    if (
      !latest ||
      latest.phase === "absent" ||
      !latest.credential ||
      latest.credential.connectedAt !== snapshotConnectedAt
    ) {
      return {
        accessToken: null,
        record: latest ?? {
          provider: PROVIDER,
          phase: "absent",
          updatedAt: t,
          updatedBy: record.updatedBy,
        },
      };
    }

    if (res.ok) {
      const raw = (await res.json()) as Record<string, unknown>;
      const nextAccess = typeof raw.access_token === "string" ? raw.access_token : "";
      const nextRefresh =
        typeof raw.refresh_token === "string" && raw.refresh_token
          ? raw.refresh_token
          : refreshToken;
      if (!nextAccess) {
        return {
          accessToken: tokenNotExpired(accessToken, t) ? accessToken : null,
          record: latest,
        };
      }
      const next: StoredOpenAICodexRecord = {
        ...latest,
        phase: "connected",
        credential: {
          ...latest.credential,
          accessTokenEnc: encryptSecret(nextAccess, key),
          refreshTokenEnc: encryptSecret(nextRefresh, key),
        },
        updatedAt: t,
      };
      await save(next);
      return { accessToken: nextAccess, record: next };
    }

    const errorCode = await readErrorCode(res);
    const permanent =
      res.status === 401 ||
      res.status === 403 ||
      errorCode === "invalid_grant" ||
      errorCode === "invalid_token" ||
      errorCode === "refresh_token_reused";

    if (permanent) {
      const next: StoredOpenAICodexRecord = {
        ...latest,
        phase: "reconnect_required",
        updatedAt: t,
      };
      await save(next);
      return { accessToken: null, record: next };
    }

    if (res.status === 429 || res.status >= 500) {
      return {
        accessToken: tokenNotExpired(accessToken, t) ? accessToken : null,
        record: latest,
      };
    }

    return {
      accessToken: tokenNotExpired(accessToken, t) ? accessToken : null,
      record: latest,
    };
  }

  async function resolveAccessTokenLocked(): Promise<string | null> {
    const current = await load();
    if (!current?.credential || current.phase === "reconnect_required") return null;
    const t = now();
    const accessToken = decryptSecret(current.credential.accessTokenEnc, key);
    if (tokenStillFresh(accessToken, t)) return accessToken;
    const result = await refreshTokens(current);
    return result.accessToken;
  }

  return {
    async startAuthorization(actorId) {
      const actor = actorId.trim();
      if (!actor) throw new Error("actorId is required");
      return withStoreLock(async () => {
        const res = await input.fetch(USERCODE_URL, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ client_id: CLIENT_ID }),
          signal: requestSignal(),
        });
        if (!res.ok) throw new Error(`openai-codex device code request failed (${res.status})`);
        const body = (await res.json()) as Record<string, unknown>;
        const deviceAuthId = typeof body.device_auth_id === "string" ? body.device_auth_id : "";
        const userCode =
          typeof body.user_code === "string"
            ? body.user_code
            : typeof body.usercode === "string"
              ? body.usercode
              : "";
        if (!deviceAuthId || !userCode) throw new Error("openai-codex device code response incomplete");
        const intervalSeconds = parseInterval(body.interval ?? body.interval_seconds);
        const t = now();
        const existing = await load();
        const record: StoredOpenAICodexRecord = {
          provider: PROVIDER,
          phase: "pending",
          ...(existing?.credential ? { credential: existing.credential } : {}),
          pending: {
            deviceAuthIdEnc: encryptSecret(deviceAuthId, key),
            userCodeEnc: encryptSecret(userCode, key),
            verificationUrl: VERIFICATION_URL,
            intervalSeconds,
            expiresAt: t + DEVICE_TTL_MS,
            nextPollAt: t + intervalSeconds * 1000,
            startedAt: t,
            startedBy: actor,
          },
          updatedAt: t,
          updatedBy: actor,
        };
        await save(record);
        return toPublic(record);
      });
    },

    async getAuthorizationStatus() {
      return withStoreLock(async () => {
        const current = await load();
        if (!current) return toPublic(null);
        if (current.phase === "connected") {
          const token = await resolveAccessTokenLocked();
          const latest = (await load()) ?? current;
          return toPublic(latest, token !== null);
        }
        if (
          current.phase === "reconnect_required" ||
          current.phase === "absent" ||
          current.phase === "denied" ||
          current.phase === "expired"
        ) {
          return toPublic(current);
        }

        if (current.exchangeEnc) {
          const payload = decryptExchange(current.exchangeEnc);
          if (!payload) {
            const denied: StoredOpenAICodexRecord = {
              ...current,
              phase: "denied",
              pending: undefined,
              exchangeEnc: undefined,
              updatedAt: now(),
            };
            await save(denied);
            return toPublic(denied);
          }
          const pending = current.pending;
          const t = now();
          if (pending && t < pending.nextPollAt) {
            return toPublic(current);
          }
          const next = await completeExchange(current, payload);
          return toPublic(next);
        }

        if (!current.pending) return toPublic(current);
        const t = now();
        if (t >= current.pending.expiresAt) {
          const expired: StoredOpenAICodexRecord = {
            ...current,
            phase: "expired",
            pending: undefined,
            exchangeEnc: undefined,
            updatedAt: t,
          };
          await save(expired);
          return toPublic(expired);
        }
        if (t < current.pending.nextPollAt) return toPublic(current);
        const next = await pollOnce(current);
        if (!(next.phase === "connected" && next.credential && !next.exchangeEnc && !next.pending)) {
          await save(next);
        }
        return toPublic(next);
      });
    },

    async cancelAuthorization(actorId) {
      const actor = actorId.trim();
      if (!actor) throw new Error("actorId is required");
      return withStoreLock(async () => {
        const current = await load();
        const t = now();
        if (!current) {
          const absent: StoredOpenAICodexRecord = {
            provider: PROVIDER,
            phase: "absent",
            updatedAt: t,
            updatedBy: actor,
          };
          await save(absent);
          return toPublic(absent);
        }
        const next: StoredOpenAICodexRecord = {
          provider: PROVIDER,
          phase: current.credential
            ? current.phase === "reconnect_required"
              ? "reconnect_required"
              : "connected"
            : "absent",
          ...(current.credential ? { credential: current.credential } : {}),
          updatedAt: t,
          updatedBy: actor,
        };
        await save(next);
        if (next.phase === "connected") {
          const token = await resolveAccessTokenLocked();
          const latest = (await load()) ?? next;
          return toPublic(latest, token !== null);
        }
        return toPublic(next);
      });
    },

    async disconnect(actorId) {
      const actor = actorId.trim();
      if (!actor) throw new Error("actorId is required");
      return withStoreLock(async () => {
        const t = now();
        const next: StoredOpenAICodexRecord = {
          provider: PROVIDER,
          phase: "absent",
          updatedAt: t,
          updatedBy: actor,
        };
        await save(next);
        return toPublic(next);
      });
    },

    async resolveAccessToken() {
      return withStoreLock(() => resolveAccessTokenLocked());
    },

    async isConfigured() {
      return withStoreLock(async () => (await resolveAccessTokenLocked()) !== null);
    },
  };
}
