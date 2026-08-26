import { test } from "node:test";
import assert from "node:assert/strict";
import { createMemoryMap } from "../src/persistence/durable-map.ts";
import { createMemoryAdvisoryLock, type AdvisoryLock } from "../src/persistence/advisory-lock.ts";
import { createOpenAICodexCredentialStore } from "../src/model/openai-codex-credential-store.ts";

const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const USERCODE_URL = "https://auth.openai.com/api/accounts/deviceauth/usercode";
const POLL_URL = "https://auth.openai.com/api/accounts/deviceauth/token";
const OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token";
const VERIFICATION_URL = "https://auth.openai.com/codex/device";
const REDIRECT_URI = "https://auth.openai.com/deviceauth/callback";
const KEY_MATERIAL = "test-openai-codex-key-material-aaaaaaaa";

const DEVICE_AUTH_ID = "device-auth-id-secret-do-not-leak";
const USER_CODE = "WDJB-MJHT";
const CODE_VERIFIER = "code-verifier-secret-do-not-leak";
const AUTH_CODE = "authorization-code-secret-do-not-leak";
const REFRESH_TOKEN = "refresh-token-secret-do-not-leak";
const REFRESH_TOKEN_ROTATED = "refresh-token-rotated-secret-do-not-leak";

const SECRET_VALUES = [DEVICE_AUTH_ID, CODE_VERIFIER, AUTH_CODE, REFRESH_TOKEN, REFRESH_TOKEN_ROTATED];

function jwtWithExp(expSeconds: number): string {
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ exp: expSeconds, sub: "codex-test" })).toString("base64url");
  return `${header}.${payload}.sig`;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function assertNoLeakedSecrets(value: unknown, extra: string[] = []): void {
  const text = JSON.stringify(value);
  for (const secret of [...SECRET_VALUES, ...extra]) {
    assert.doesNotMatch(text, new RegExp(escapeRegExp(secret)));
  }
  assert.doesNotMatch(text, /deviceAuthId|codeVerifier|authorizationCode|accessToken|refreshToken|"v2:/);
}

function assertBackingHasNoPlaintextSecrets(snap: unknown): void {
  const text = JSON.stringify(snap);
  for (const secret of SECRET_VALUES) {
    assert.doesNotMatch(text, new RegExp(escapeRegExp(secret)));
  }
  assert.doesNotMatch(text, /"authorizationCode"\s*:/);
  assert.doesNotMatch(text, /"codeVerifier"\s*:/);
  assert.doesNotMatch(text, /authorization-code-secret|code-verifier-secret/);
}

type FetchCall = { url: string; init?: RequestInit };

function createHarness(
  opts: {
    now?: { t: number };
    backing?: ReturnType<typeof createMemoryMap>;
    advisoryLock?: AdvisoryLock;
    fetchShared?: { handler: (url: string, init?: RequestInit) => Promise<Response>; calls: FetchCall[] };
    requestTimeoutMs?: number;
  } = {},
) {
  const clock = opts.now ?? { t: 1_700_000_000_000 };
  const backing = opts.backing ?? createMemoryMap<unknown>();
  const shared = opts.fetchShared ?? {
    calls: [] as FetchCall[],
    handler: async () => new Response("unexpected", { status: 500 }),
  };

  const fetchImpl: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    shared.calls.push({ url, init });
    const signal = init?.signal;
    if (signal?.aborted) {
      throw signal.reason ?? new DOMException("The operation was aborted", "AbortError");
    }
    return new Promise<Response>((resolve, reject) => {
      const onAbort = () => {
        reject(signal?.reason ?? new DOMException("The operation was aborted", "AbortError"));
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      Promise.resolve(shared.handler(url, init)).then(
        (res) => {
          signal?.removeEventListener("abort", onAbort);
          if (signal?.aborted) {
            reject(signal.reason ?? new DOMException("The operation was aborted", "AbortError"));
            return;
          }
          resolve(res);
        },
        (err) => {
          signal?.removeEventListener("abort", onAbort);
          reject(err);
        },
      );
    });
  };

  const store = createOpenAICodexCredentialStore({
    backing: backing as never,
    keyMaterial: KEY_MATERIAL,
    fetch: fetchImpl,
    now: () => clock.t,
    advisoryLock: opts.advisoryLock ?? createMemoryAdvisoryLock(),
    ...(opts.requestTimeoutMs !== undefined ? { requestTimeoutMs: opts.requestTimeoutMs } : {}),
  });

  return {
    store,
    backing,
    calls: shared.calls,
    clock,
    setHandler(next: (url: string, init?: RequestInit) => Promise<Response>) {
      shared.handler = next;
    },
  };
}

function neverResolvingResponse(): Promise<Response> {
  return new Promise(() => {});
}

async function connectStore(
  h: ReturnType<typeof createHarness>,
  access: string,
  refresh = REFRESH_TOKEN,
): Promise<void> {
  h.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await h.store.startAuthorization("admin");
  h.clock.t += 3_000;
  h.setHandler(async (url) => {
    if (url === POLL_URL) {
      return Response.json({
        authorization_code: AUTH_CODE,
        code_verifier: CODE_VERIFIER,
        code_challenge: "c",
      });
    }
    return Response.json({ access_token: access, refresh_token: refresh });
  });
  assert.equal((await h.store.getAuthorizationStatus()).phase, "connected");
}

async function backingSnapshot(backing: ReturnType<typeof createMemoryMap>): Promise<unknown> {
  return Object.fromEntries(await backing.entries());
}

test("startAuthorization returns redacted pending status and encrypts durable secrets", async () => {
  const h = createHarness();
  h.setHandler(async (url, init) => {
    assert.equal(url, USERCODE_URL);
    assert.equal(init?.method, "POST");
    assert.deepEqual(JSON.parse(String(init?.body)), { client_id: CLIENT_ID });
    return Response.json({
      device_auth_id: DEVICE_AUTH_ID,
      user_code: USER_CODE,
      interval: "5",
    });
  });

  const status = await h.store.startAuthorization("admin-alice");
  assert.equal(status.provider, "openai-codex");
  assert.equal(status.phase, "pending");
  assert.equal(status.configured, false);
  assert.equal(status.verificationUrl, VERIFICATION_URL);
  assert.equal(status.userCode, USER_CODE);
  assert.equal(status.intervalSeconds, 5);
  assert.equal(status.expiresAt, h.clock.t + 15 * 60_000);
  assert.equal(status.updatedBy, "admin-alice");
  assertNoLeakedSecrets(status);

  const snap = await backingSnapshot(h.backing);
  const text = JSON.stringify(snap);
  assert.match(text, /"v2:/);
  for (const secret of [DEVICE_AUTH_ID, USER_CODE, CODE_VERIFIER, AUTH_CODE]) {
    assert.doesNotMatch(text, new RegExp(escapeRegExp(secret)));
  }
  assert.equal(h.calls.length, 1);
});

test("getAuthorizationStatus does not poll before nextPollAt", async () => {
  const h = createHarness();
  h.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await h.store.startAuthorization("admin");
  h.calls.length = 0;
  h.setHandler(async () => {
    throw new Error("poll must not run");
  });

  const status = await h.store.getAuthorizationStatus();
  assert.equal(status.phase, "pending");
  assert.equal(h.calls.length, 0);
});

test("poll stays pending on 403 and authorization_pending", async () => {
  const h = createHarness();
  h.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await h.store.startAuthorization("admin");
  h.clock.t += 3_000;
  h.calls.length = 0;

  let polls = 0;
  h.setHandler(async (url) => {
    assert.equal(url, POLL_URL);
    polls += 1;
    if (polls === 1) return new Response("forbidden", { status: 403 });
    return Response.json({ error: "authorization_pending" }, { status: 400 });
  });

  assert.equal((await h.store.getAuthorizationStatus()).phase, "pending");
  h.clock.t += 3_000;
  assert.equal((await h.store.getAuthorizationStatus()).phase, "pending");
  assert.equal(polls, 2);
});

test("slow_down respects Retry-After and increases interval", async () => {
  const h = createHarness();
  h.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await h.store.startAuthorization("admin");
  h.clock.t += 3_000;

  h.setHandler(async () => new Response(JSON.stringify({ error: "slow_down" }), { status: 429, headers: { "retry-after": "9" } }));
  const status = await h.store.getAuthorizationStatus();
  assert.equal(status.phase, "slow_down");
  assert.equal(status.intervalSeconds, 9);

  h.calls.length = 0;
  h.clock.t += 3_000;
  assert.equal((await h.store.getAuthorizationStatus()).phase, "slow_down");
  assert.equal(h.calls.length, 0);

  h.clock.t += 6_000;
  h.setHandler(async () => new Response("still waiting", { status: 404 }));
  assert.equal((await h.store.getAuthorizationStatus()).phase, "pending");
});

test("denied and expired terminal phases", async () => {
  const denied = createHarness();
  denied.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await denied.store.startAuthorization("admin");
  denied.clock.t += 3_000;
  denied.setHandler(async () => new Response("nope", { status: 400 }));
  assert.equal((await denied.store.getAuthorizationStatus()).phase, "denied");
  assertNoLeakedSecrets(await denied.store.getAuthorizationStatus());

  const expired = createHarness();
  expired.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await expired.store.startAuthorization("admin");
  expired.clock.t += 15 * 60_000 + 1;
  expired.setHandler(async () => {
    throw new Error("expired must not poll");
  });
  assert.equal((await expired.store.getAuthorizationStatus()).phase, "expired");

  const gone = createHarness();
  gone.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await gone.store.startAuthorization("admin");
  gone.clock.t += 3_000;
  gone.setHandler(async () => new Response("gone", { status: 410 }));
  assert.equal((await gone.store.getAuthorizationStatus()).phase, "expired");
});

test("successful poll exchanges exact form fields and connects", async () => {
  const h = createHarness();
  const access = jwtWithExp(Math.floor(h.clock.t / 1000) + 3600);
  h.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await h.store.startAuthorization("admin");
  h.clock.t += 3_000;
  h.calls.length = 0;

  h.setHandler(async (url, init) => {
    if (url === POLL_URL) {
      assert.deepEqual(JSON.parse(String(init?.body)), {
        device_auth_id: DEVICE_AUTH_ID,
        user_code: USER_CODE,
      });
      return Response.json({
        authorization_code: AUTH_CODE,
        code_verifier: CODE_VERIFIER,
        code_challenge: "challenge",
      });
    }
    if (url === OAUTH_TOKEN_URL) {
      assert.equal(init?.method, "POST");
      assert.match(String(init?.headers && new Headers(init.headers).get("content-type")), /application\/x-www-form-urlencoded/);
      const body = new URLSearchParams(String(init?.body));
      assert.equal(body.get("grant_type"), "authorization_code");
      assert.equal(body.get("code"), AUTH_CODE);
      assert.equal(body.get("redirect_uri"), REDIRECT_URI);
      assert.equal(body.get("client_id"), CLIENT_ID);
      assert.equal(body.get("code_verifier"), CODE_VERIFIER);
      assert.equal([...body.keys()].sort().join(","), "client_id,code,code_verifier,grant_type,redirect_uri");
      return Response.json({
        access_token: access,
        refresh_token: REFRESH_TOKEN,
        token_type: "Bearer",
      });
    }
    throw new Error(`unexpected url ${url}`);
  });

  const status = await h.store.getAuthorizationStatus();
  assert.equal(status.phase, "connected");
  assert.equal(status.configured, true);
  assert.equal(status.verificationUrl, undefined);
  assert.equal(status.userCode, undefined);
  assertNoLeakedSecrets(status, [access]);
  assert.equal(await h.store.isConfigured(), true);
  assert.equal(await h.store.resolveAccessToken(), access);

  const snap = JSON.stringify(await backingSnapshot(h.backing));
  for (const secret of [...SECRET_VALUES, access, USER_CODE]) {
    assert.doesNotMatch(snap, new RegExp(escapeRegExp(secret)));
  }
});

test("cancel clears pending but keeps connected credential; disconnect removes both", async () => {
  const h = createHarness();
  const access = jwtWithExp(Math.floor(h.clock.t / 1000) + 3600);
  h.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await h.store.startAuthorization("first");
  h.clock.t += 3_000;
  h.setHandler(async (url) => {
    if (url === POLL_URL) {
      return Response.json({
        authorization_code: AUTH_CODE,
        code_verifier: CODE_VERIFIER,
        code_challenge: "c",
      });
    }
    return Response.json({ access_token: access, refresh_token: REFRESH_TOKEN });
  });
  assert.equal((await h.store.getAuthorizationStatus()).phase, "connected");

  h.setHandler(async () =>
    Response.json({
      device_auth_id: `${DEVICE_AUTH_ID}-2`,
      user_code: "AAAA-BBBB",
      interval: 3,
    }),
  );
  const pending = await h.store.startAuthorization("second");
  assert.equal(pending.phase, "pending");
  assert.equal(pending.configured, true);
  assert.equal(await h.store.resolveAccessToken(), access);

  const cancelled = await h.store.cancelAuthorization("canceller");
  assert.equal(cancelled.phase, "connected");
  assert.equal(cancelled.configured, true);
  assert.equal(await h.store.resolveAccessToken(), access);

  const disconnected = await h.store.disconnect("admin");
  assert.equal(disconnected.phase, "absent");
  assert.equal(disconnected.configured, false);
  assert.equal(await h.store.resolveAccessToken(), null);
  assert.equal(await h.store.isConfigured(), false);
});

test("resolveAccessToken refreshes within 120s skew and rotates refresh token", async () => {
  const h = createHarness();
  const nowSec = Math.floor(h.clock.t / 1000);
  const nearExpiry = jwtWithExp(nowSec + 90);
  const refreshed = jwtWithExp(nowSec + 3600);

  h.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await h.store.startAuthorization("admin");
  h.clock.t += 3_000;
  h.setHandler(async (url) => {
    if (url === POLL_URL) {
      return Response.json({
        authorization_code: AUTH_CODE,
        code_verifier: CODE_VERIFIER,
        code_challenge: "c",
      });
    }
    return Response.json({ access_token: nearExpiry, refresh_token: REFRESH_TOKEN });
  });
  await h.store.getAuthorizationStatus();
  h.calls.length = 0;

  h.setHandler(async (url, init) => {
    assert.equal(url, OAUTH_TOKEN_URL);
    const body = new URLSearchParams(String(init?.body));
    assert.equal(body.get("grant_type"), "refresh_token");
    assert.equal(body.get("refresh_token"), REFRESH_TOKEN);
    assert.equal(body.get("client_id"), CLIENT_ID);
    return Response.json({ access_token: refreshed, refresh_token: REFRESH_TOKEN_ROTATED });
  });

  assert.equal(await h.store.resolveAccessToken(), refreshed);
  assert.equal(h.calls.length, 1);

  h.calls.length = 0;
  h.setHandler(async () => {
    throw new Error("unexpired token must not refresh");
  });
  assert.equal(await h.store.resolveAccessToken(), refreshed);
  assert.equal(h.calls.length, 0);

  h.clock.t += 3480 * 1000;
  h.calls.length = 0;
  let refreshCount = 0;
  h.setHandler(async (_url, init) => {
    refreshCount += 1;
    const body = new URLSearchParams(String(init?.body));
    assert.equal(body.get("refresh_token"), REFRESH_TOKEN_ROTATED);
    return Response.json({ access_token: jwtWithExp(Math.floor(h.clock.t / 1000) + 3600), refresh_token: "next" });
  });
  assert.ok(await h.store.resolveAccessToken());
  assert.equal(refreshCount, 1);
});

test("concurrent resolveAccessToken single-flights one refresh", async () => {
  const h = createHarness();
  const nowSec = Math.floor(h.clock.t / 1000);
  const nearExpiry = jwtWithExp(nowSec + 30);
  const refreshed = jwtWithExp(nowSec + 3600);

  h.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await h.store.startAuthorization("admin");
  h.clock.t += 3_000;
  h.setHandler(async (url) => {
    if (url === POLL_URL) {
      return Response.json({
        authorization_code: AUTH_CODE,
        code_verifier: CODE_VERIFIER,
        code_challenge: "c",
      });
    }
    return Response.json({ access_token: nearExpiry, refresh_token: REFRESH_TOKEN });
  });
  await h.store.getAuthorizationStatus();

  let refreshCalls = 0;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  h.setHandler(async () => {
    refreshCalls += 1;
    await gate;
    return Response.json({ access_token: refreshed, refresh_token: REFRESH_TOKEN_ROTATED });
  });

  const first = h.store.resolveAccessToken();
  const second = h.store.resolveAccessToken();
  release();
  assert.equal(await first, refreshed);
  assert.equal(await second, refreshed);
  assert.equal(refreshCalls, 1);
});

test("permanent refresh failure becomes reconnect_required; transient keeps prior token", async () => {
  const permanent = createHarness();
  const nowSec = Math.floor(permanent.clock.t / 1000);
  const nearExpiry = jwtWithExp(nowSec + 60);
  permanent.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await permanent.store.startAuthorization("admin");
  permanent.clock.t += 3_000;
  permanent.setHandler(async (url) => {
    if (url === POLL_URL) {
      return Response.json({
        authorization_code: AUTH_CODE,
        code_verifier: CODE_VERIFIER,
        code_challenge: "c",
      });
    }
    return Response.json({ access_token: nearExpiry, refresh_token: REFRESH_TOKEN });
  });
  await permanent.store.getAuthorizationStatus();
  permanent.setHandler(async () => Response.json({ error: "invalid_grant" }, { status: 400 }));
  assert.equal(await permanent.store.resolveAccessToken(), null);
  assert.equal((await permanent.store.getAuthorizationStatus()).phase, "reconnect_required");
  assert.equal(await permanent.store.isConfigured(), false);
  assertNoLeakedSecrets(await permanent.store.getAuthorizationStatus(), [nearExpiry]);

  const transient = createHarness();
  const stillValid = jwtWithExp(Math.floor(transient.clock.t / 1000) + 90);
  transient.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await transient.store.startAuthorization("admin");
  transient.clock.t += 3_000;
  transient.setHandler(async (url) => {
    if (url === POLL_URL) {
      return Response.json({
        authorization_code: AUTH_CODE,
        code_verifier: CODE_VERIFIER,
        code_challenge: "c",
      });
    }
    return Response.json({ access_token: stillValid, refresh_token: REFRESH_TOKEN });
  });
  await transient.store.getAuthorizationStatus();
  transient.setHandler(async () => new Response("rate", { status: 429 }));
  assert.equal(await transient.store.resolveAccessToken(), stillValid);
  assert.equal((await transient.store.getAuthorizationStatus()).phase, "connected");
  assert.equal(await transient.store.isConfigured(), true);

  transient.clock.t += 200_000;
  transient.setHandler(async () => {
    throw new Error("network down");
  });
  assert.equal(await transient.store.resolveAccessToken(), null);
  assert.equal((await transient.store.getAuthorizationStatus()).phase, "connected");
});

test("5xx during poll keeps retryable pending without leaking body", async () => {
  const h = createHarness();
  h.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await h.store.startAuthorization("admin");
  h.clock.t += 3_000;
  h.setHandler(async () => new Response("upstream secret boom token=abc", { status: 503 }));
  const status = await h.store.getAuthorizationStatus();
  assert.equal(status.phase, "pending");
  assertNoLeakedSecrets(status, ["upstream secret boom token=abc"]);
});

test("poll stays pending on real deviceauth_authorization_pending string and object shapes", async () => {
  const h = createHarness();
  h.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await h.store.startAuthorization("admin");
  h.clock.t += 3_000;
  h.calls.length = 0;

  let polls = 0;
  h.setHandler(async (url) => {
    assert.equal(url, POLL_URL);
    polls += 1;
    if (polls === 1) {
      return Response.json({ error: "deviceauth_authorization_pending" }, { status: 400 });
    }
    return Response.json(
      { error: { code: "deviceauth_authorization_pending", message: "wait" } },
      { status: 400 },
    );
  });

  assert.equal((await h.store.getAuthorizationStatus()).phase, "pending");
  h.clock.t += 3_000;
  assert.equal((await h.store.getAuthorizationStatus()).phase, "pending");
  assert.equal(polls, 2);
});

test("startAuthorization accepts usercode alias", async () => {
  const h = createHarness();
  h.setHandler(async () =>
    Response.json({
      device_auth_id: DEVICE_AUTH_ID,
      usercode: USER_CODE,
      interval: 4,
    }),
  );
  const status = await h.store.startAuthorization("admin");
  assert.equal(status.phase, "pending");
  assert.equal(status.userCode, USER_CODE);
  assert.equal(status.intervalSeconds, 4);
});

test("exchange 503 persists encrypted durable retry then next status only retries exchange", async () => {
  const h = createHarness();
  const access = jwtWithExp(Math.floor(h.clock.t / 1000) + 3600);
  h.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await h.store.startAuthorization("admin");
  h.clock.t += 3_000;
  h.calls.length = 0;

  let exchangeAttempts = 0;
  h.setHandler(async (url) => {
    if (url === POLL_URL) {
      return Response.json({
        authorization_code: AUTH_CODE,
        code_verifier: CODE_VERIFIER,
        code_challenge: "c",
      });
    }
    if (url === OAUTH_TOKEN_URL) {
      exchangeAttempts += 1;
      if (exchangeAttempts === 1) return new Response("busy", { status: 503 });
      return Response.json({ access_token: access, refresh_token: REFRESH_TOKEN });
    }
    throw new Error(`unexpected url ${url}`);
  });

  const first = await h.store.getAuthorizationStatus();
  assert.equal(first.phase, "pending");
  assert.equal(exchangeAttempts, 1);
  assert.equal(h.calls.filter((c) => c.url === POLL_URL).length, 1);
  assert.equal(h.calls.filter((c) => c.url === OAUTH_TOKEN_URL).length, 1);

  const midSnap = await backingSnapshot(h.backing);
  assertBackingHasNoPlaintextSecrets(midSnap);
  const midText = JSON.stringify(midSnap);
  assert.match(midText, /"v2:/);
  assert.match(midText, /exchangeEnc/);

  h.calls.length = 0;
  h.clock.t += 3_000;
  const second = await h.store.getAuthorizationStatus();
  assert.equal(second.phase, "connected");
  assert.equal(second.configured, true);
  assert.equal(exchangeAttempts, 2);
  assert.equal(h.calls.filter((c) => c.url === POLL_URL).length, 0);
  assert.equal(h.calls.filter((c) => c.url === OAUTH_TOKEN_URL).length, 1);
  assertBackingHasNoPlaintextSecrets(await backingSnapshot(h.backing));
});

test("exchange network failure keeps durable retry state without plaintext secrets", async () => {
  const h = createHarness();
  h.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await h.store.startAuthorization("admin");
  h.clock.t += 3_000;

  h.setHandler(async (url) => {
    if (url === POLL_URL) {
      return Response.json({
        authorization_code: AUTH_CODE,
        code_verifier: CODE_VERIFIER,
        code_challenge: "c",
      });
    }
    if (url === OAUTH_TOKEN_URL) throw new Error("network down");
    throw new Error(`unexpected url ${url}`);
  });

  assert.equal((await h.store.getAuthorizationStatus()).phase, "pending");
  assertBackingHasNoPlaintextSecrets(await backingSnapshot(h.backing));
  assert.match(JSON.stringify(await backingSnapshot(h.backing)), /exchangeEnc/);
});

test("two stores with shared backing and advisory lock single-flight concurrent refresh", async () => {
  const clock = { t: 1_700_000_000_000 };
  const backing = createMemoryMap<unknown>();
  const lock = createMemoryAdvisoryLock();
  const shared = {
    calls: [] as FetchCall[],
    handler: async () => new Response("unexpected", { status: 500 }),
  };
  const left = createHarness({ now: clock, backing, advisoryLock: lock, fetchShared: shared });
  const right = createHarness({ now: clock, backing, advisoryLock: lock, fetchShared: shared });
  const nowSec = Math.floor(clock.t / 1000);
  const nearExpiry = jwtWithExp(nowSec + 30);
  const refreshed = jwtWithExp(nowSec + 3600);

  await connectStore(left, nearExpiry);
  shared.calls.length = 0;

  let refreshCalls = 0;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  left.setHandler(async (url) => {
    assert.equal(url, OAUTH_TOKEN_URL);
    refreshCalls += 1;
    await gate;
    return Response.json({ access_token: refreshed, refresh_token: REFRESH_TOKEN_ROTATED });
  });

  const first = left.store.resolveAccessToken();
  const second = right.store.resolveAccessToken();
  release();
  assert.equal(await first, refreshed);
  assert.equal(await second, refreshed);
  assert.equal(refreshCalls, 1);
  assert.equal(shared.calls.filter((c) => c.url === OAUTH_TOKEN_URL).length, 1);
  assert.equal((await left.store.getAuthorizationStatus()).phase, "connected");
  assert.equal((await right.store.getAuthorizationStatus()).phase, "connected");
});

test("two stores with shared backing and advisory lock single-flight concurrent status", async () => {
  const clock = { t: 1_700_000_000_000 };
  const backing = createMemoryMap<unknown>();
  const lock = createMemoryAdvisoryLock();
  const shared = {
    calls: [] as FetchCall[],
    handler: async () => new Response("unexpected", { status: 500 }),
  };
  const left = createHarness({ now: clock, backing, advisoryLock: lock, fetchShared: shared });
  const right = createHarness({ now: clock, backing, advisoryLock: lock, fetchShared: shared });
  const access = jwtWithExp(Math.floor(clock.t / 1000) + 3600);

  left.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await left.store.startAuthorization("admin");
  clock.t += 3_000;
  shared.calls.length = 0;

  let polls = 0;
  let exchanges = 0;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  left.setHandler(async (url) => {
    if (url === POLL_URL) {
      polls += 1;
      await gate;
      return Response.json({
        authorization_code: AUTH_CODE,
        code_verifier: CODE_VERIFIER,
        code_challenge: "c",
      });
    }
    if (url === OAUTH_TOKEN_URL) {
      exchanges += 1;
      return Response.json({ access_token: access, refresh_token: REFRESH_TOKEN });
    }
    throw new Error(`unexpected url ${url}`);
  });

  const first = left.store.getAuthorizationStatus();
  const second = right.store.getAuthorizationStatus();
  release();
  assert.equal((await first).phase, "connected");
  assert.equal((await second).phase, "connected");
  assert.equal(polls, 1);
  assert.equal(exchanges, 1);
});

test("disconnect waits for in-flight refresh and ends absent without resurrection", async () => {
  const h = createHarness();
  const nowSec = Math.floor(h.clock.t / 1000);
  const nearExpiry = jwtWithExp(nowSec + 30);
  const refreshed = jwtWithExp(nowSec + 3600);
  await connectStore(h, nearExpiry);

  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  let refreshStarted = false;
  h.setHandler(async () => {
    refreshStarted = true;
    await gate;
    return Response.json({ access_token: refreshed, refresh_token: REFRESH_TOKEN_ROTATED });
  });

  const refreshPromise = h.store.resolveAccessToken();
  while (!refreshStarted) await new Promise((r) => setTimeout(r, 1));
  const disconnectPromise = h.store.disconnect("admin");
  release();
  await refreshPromise;
  const disconnected = await disconnectPromise;
  assert.equal(disconnected.phase, "absent");
  assert.equal(await h.store.resolveAccessToken(), null);
  assert.equal(await h.store.isConfigured(), false);
  assert.equal((await h.store.getAuthorizationStatus()).phase, "absent");
});

test("isConfigured uses locked resolver: expired+transient is false; unexpired fallback stays true", async () => {
  const h = createHarness();
  const nowSec = Math.floor(h.clock.t / 1000);
  const stillValid = jwtWithExp(nowSec + 90);
  await connectStore(h, stillValid);

  h.setHandler(async () => new Response("rate", { status: 429 }));
  assert.equal(await h.store.resolveAccessToken(), stillValid);
  assert.equal(await h.store.isConfigured(), true);
  assert.equal((await h.store.getAuthorizationStatus()).phase, "connected");

  h.clock.t += 200_000;
  h.setHandler(async () => {
    throw new Error("network down");
  });
  assert.equal(await h.store.resolveAccessToken(), null);
  assert.equal(await h.store.isConfigured(), false);
  assert.equal((await h.store.getAuthorizationStatus()).phase, "connected");
});

test("slow_down respects HTTP-date Retry-After with minimum three seconds", async () => {
  const h = createHarness();
  h.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await h.store.startAuthorization("admin");
  h.clock.t += 3_000;

  const retryAt = new Date(h.clock.t + 12_000).toUTCString();
  h.setHandler(
    async () =>
      new Response(JSON.stringify({ error: "slow_down" }), {
        status: 429,
        headers: { "retry-after": retryAt },
      }),
  );
  const status = await h.store.getAuthorizationStatus();
  assert.equal(status.phase, "slow_down");
  assert.equal(status.intervalSeconds, 12);

  h.calls.length = 0;
  h.clock.t += 3_000;
  assert.equal((await h.store.getAuthorizationStatus()).phase, "slow_down");
  assert.equal(h.calls.length, 0);

  const short = createHarness();
  short.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await short.store.startAuthorization("admin");
  short.clock.t += 3_000;
  const soon = new Date(short.clock.t + 1_000).toUTCString();
  short.setHandler(
    async () =>
      new Response(JSON.stringify({ error: "slow_down" }), {
        status: 429,
        headers: { "retry-after": soon },
      }),
  );
  assert.equal((await short.store.getAuthorizationStatus()).intervalSeconds, 3);
});

test("exchange 200 persists connected durably before status returns (save-gated)", async () => {
  const backing = createMemoryMap<unknown>();
  const realPut = backing.put.bind(backing);
  let releaseConnectedSave!: () => void;
  const connectedSaveGate = new Promise<void>((resolve) => {
    releaseConnectedSave = resolve;
  });
  let connectedSaveStarted = false;
  let statusSettled = false;
  let connectedSaveCount = 0;
  backing.put = async (key, value) => {
    const record = value as { phase?: string; credential?: unknown; exchangeEnc?: unknown; pending?: unknown };
    if (record.phase === "connected" && record.credential) {
      connectedSaveCount += 1;
      assert.equal(connectedSaveCount, 1);
      connectedSaveStarted = true;
      assert.equal(statusSettled, false);
      assert.equal(record.exchangeEnc, undefined);
      assert.equal(record.pending, undefined);
      await connectedSaveGate;
    }
    return realPut(key, value);
  };

  const h = createHarness({ backing });
  const access = jwtWithExp(Math.floor(h.clock.t / 1000) + 3600);
  h.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await h.store.startAuthorization("admin");
  h.clock.t += 3_000;
  h.setHandler(async (url) => {
    if (url === POLL_URL) {
      return Response.json({
        authorization_code: AUTH_CODE,
        code_verifier: CODE_VERIFIER,
        code_challenge: "c",
      });
    }
    if (url === OAUTH_TOKEN_URL) {
      return Response.json({ access_token: access, refresh_token: REFRESH_TOKEN });
    }
    throw new Error(`unexpected url ${url}`);
  });

  const statusPromise = h.store.getAuthorizationStatus().then((status) => {
    statusSettled = true;
    return status;
  });
  while (!connectedSaveStarted) await new Promise((r) => setTimeout(r, 1));
  assert.equal(statusSettled, false);
  const mid = (await backing.get("openai-codex")) as {
    phase?: string;
    exchangeEnc?: string;
    credential?: unknown;
  };
  assert.ok(mid?.exchangeEnc);
  assert.equal(mid?.credential, undefined);
  releaseConnectedSave();
  const status = await statusPromise;
  assert.equal(status.phase, "connected");
  assert.equal(status.configured, true);
  assert.equal(connectedSaveCount, 1);
  const durable = (await backing.get("openai-codex")) as {
    phase: string;
    exchangeEnc?: string;
    pending?: unknown;
    credential?: unknown;
  };
  assert.equal(durable.phase, "connected");
  assert.equal(durable.exchangeEnc, undefined);
  assert.equal(durable.pending, undefined);
  assert.ok(durable.credential);
});

test("exchangeEnc survives device TTL expiry and retries to connected", async () => {
  const h = createHarness();
  const access = jwtWithExp(Math.floor(h.clock.t / 1000) + 3600);
  h.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await h.store.startAuthorization("admin");
  const startedExpiresAt = (await h.store.getAuthorizationStatus()).expiresAt!;
  h.clock.t += 3_000;

  let exchangeAttempts = 0;
  h.setHandler(async (url) => {
    if (url === POLL_URL) {
      return Response.json({
        authorization_code: AUTH_CODE,
        code_verifier: CODE_VERIFIER,
        code_challenge: "c",
      });
    }
    if (url === OAUTH_TOKEN_URL) {
      exchangeAttempts += 1;
      if (exchangeAttempts === 1) return new Response("busy", { status: 503 });
      return Response.json({ access_token: access, refresh_token: REFRESH_TOKEN });
    }
    throw new Error(`unexpected url ${url}`);
  });

  assert.equal((await h.store.getAuthorizationStatus()).phase, "pending");
  assert.equal(exchangeAttempts, 1);
  assert.match(JSON.stringify(await backingSnapshot(h.backing)), /exchangeEnc/);

  h.clock.t = startedExpiresAt + 1;
  h.calls.length = 0;
  const afterExpiry = await h.store.getAuthorizationStatus();
  assert.equal(afterExpiry.phase, "connected");
  assert.equal(afterExpiry.configured, true);
  assert.equal(exchangeAttempts, 2);
  assert.equal(h.calls.filter((c) => c.url === POLL_URL).length, 0);
  assert.equal(h.calls.filter((c) => c.url === OAUTH_TOKEN_URL).length, 1);
});

test("hung poll/exchange/refresh abort as transient and release lock for cancel", async () => {
  const lock = createMemoryAdvisoryLock();
  const pollH = createHarness({ advisoryLock: lock, requestTimeoutMs: 40 });
  pollH.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await pollH.store.startAuthorization("admin");
  pollH.clock.t += 3_000;
  pollH.setHandler(async (url, init) => {
    if (url !== POLL_URL) throw new Error(`unexpected url ${url}`);
    if (!init?.signal) throw new Error("missing abort signal");
    return neverResolvingResponse();
  });
  assert.equal((await pollH.store.getAuthorizationStatus()).phase, "pending");
  assert.equal((await pollH.store.cancelAuthorization("admin")).phase, "absent");

  const exchangeH = createHarness({ advisoryLock: createMemoryAdvisoryLock(), requestTimeoutMs: 40 });
  exchangeH.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  await exchangeH.store.startAuthorization("admin");
  exchangeH.clock.t += 3_000;
  exchangeH.setHandler(async (url, init) => {
    if (url === POLL_URL) {
      return Response.json({
        authorization_code: AUTH_CODE,
        code_verifier: CODE_VERIFIER,
        code_challenge: "c",
      });
    }
    if (url === OAUTH_TOKEN_URL) {
      if (!init?.signal) throw new Error("missing abort signal");
      return neverResolvingResponse();
    }
    throw new Error(`unexpected url ${url}`);
  });
  assert.equal((await exchangeH.store.getAuthorizationStatus()).phase, "pending");
  assert.match(JSON.stringify(await backingSnapshot(exchangeH.backing)), /exchangeEnc/);
  assert.equal((await exchangeH.store.cancelAuthorization("admin")).phase, "absent");

  const refreshH = createHarness({ advisoryLock: createMemoryAdvisoryLock(), requestTimeoutMs: 40 });
  const nowSec = Math.floor(refreshH.clock.t / 1000);
  await connectStore(refreshH, jwtWithExp(nowSec + 30));
  refreshH.clock.t += 200_000;
  refreshH.setHandler(async (url, init) => {
    if (url !== OAUTH_TOKEN_URL) throw new Error(`unexpected url ${url}`);
    if (!init?.signal) throw new Error("missing abort signal");
    return neverResolvingResponse();
  });
  assert.equal(await refreshH.store.resolveAccessToken(), null);
  assert.equal((await refreshH.store.disconnect("admin")).phase, "absent");
});

test("hung usercode start times out and releases lock", async () => {
  const lock = createMemoryAdvisoryLock();
  const h = createHarness({ advisoryLock: lock, requestTimeoutMs: 40 });
  h.setHandler(async (_url, init) => {
    if (!init?.signal) throw new Error("missing abort signal");
    return neverResolvingResponse();
  });
  const startPromise = h.store.startAuthorization("admin");
  const raced = await Promise.race([
    startPromise.then(
      () => "resolved" as const,
      (err: unknown) => err,
    ),
    new Promise<"hung">((resolve) => setTimeout(() => resolve("hung"), 200)),
  ]);
  assert.notEqual(raced, "hung");
  assert.ok(raced instanceof Error);
  h.setHandler(async () =>
    Response.json({ device_auth_id: DEVICE_AUTH_ID, user_code: USER_CODE, interval: 3 }),
  );
  const status = await h.store.startAuthorization("admin");
  assert.equal(status.phase, "pending");
  assert.equal((await h.store.cancelAuthorization("admin")).phase, "absent");
});

test("GET status configured false when connected access expired and refresh transient", async () => {
  const h = createHarness();
  const nowSec = Math.floor(h.clock.t / 1000);
  await connectStore(h, jwtWithExp(nowSec + 90));
  h.clock.t += 200_000;
  h.setHandler(async () => {
    throw new Error("network down");
  });
  const status = await h.store.getAuthorizationStatus();
  assert.equal(status.phase, "connected");
  assert.equal(status.configured, false);
  assert.equal(await h.store.isConfigured(), false);
});

test("cancel after reconnect start reports configured false when access still unresolvable", async () => {
  const h = createHarness();
  const nowSec = Math.floor(h.clock.t / 1000);
  await connectStore(h, jwtWithExp(nowSec + 90));
  h.clock.t += 200_000;
  h.setHandler(async () => {
    throw new Error("network down");
  });
  const degraded = await h.store.getAuthorizationStatus();
  assert.equal(degraded.phase, "connected");
  assert.equal(degraded.configured, false);

  h.setHandler(async () =>
    Response.json({
      device_auth_id: `${DEVICE_AUTH_ID}-2`,
      user_code: "AAAA-BBBB",
      interval: 3,
    }),
  );
  assert.equal((await h.store.startAuthorization("second")).phase, "pending");

  h.setHandler(async () => {
    throw new Error("network down");
  });
  const cancelled = await h.store.cancelAuthorization("canceller");
  assert.equal(cancelled.phase, "connected");
  assert.equal(cancelled.configured, false);
  assert.equal(await h.store.isConfigured(), false);
});
