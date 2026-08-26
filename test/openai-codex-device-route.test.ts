import "./support/auto-fake-sprites.ts";

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createInsecureTestServer } from "../src/api/server.ts";
import type {
  OpenAICodexCredentialStore,
  OpenAICodexPublicStatus,
} from "../src/model/openai-codex-credential-store.ts";
import { buildApp, type BuiltApp } from "../src/wiring.ts";
import { testConfig } from "./support/test-config.ts";

const ADMIN = { "content-type": "application/json", "x-admin-actor": "admin-alice@default-org" };
const NON_ADMIN = { "content-type": "application/json", "x-admin-actor": "nobody@default-org" };

const BASE = "/v1/admin/model-providers/openai-codex";
const DEVICE = `${BASE}/device`;

const FORBIDDEN_KEYS = [
  "access_token",
  "refresh_token",
  "deviceAuthId",
  "codeVerifier",
  "authorizationCode",
  "secretEnc",
] as const;

function assertNoPrivateFields(value: unknown): void {
  const text = JSON.stringify(value);
  for (const key of FORBIDDEN_KEYS) {
    assert.doesNotMatch(text, new RegExp(`"${key}"`));
    assert.doesNotMatch(text, new RegExp(key));
  }
}

function publicStatus(overrides: Partial<OpenAICodexPublicStatus> = {}): OpenAICodexPublicStatus {
  return {
    provider: "openai-codex",
    phase: "pending",
    configured: false,
    verificationUrl: "https://auth.openai.com/codex/device",
    userCode: "WDJB-MJHT",
    intervalSeconds: 5,
    expiresAt: 1_700_000_900_000,
    updatedAt: 1_700_000_000_000,
    updatedBy: "admin-alice",
    ...overrides,
  };
}

function fakeStore(seed: OpenAICodexPublicStatus = publicStatus()): {
  store: OpenAICodexCredentialStore;
  calls: Array<{ method: string; actorId?: string }>;
} {
  let current = seed;
  const calls: Array<{ method: string; actorId?: string }> = [];
  const store: OpenAICodexCredentialStore = {
    async startAuthorization(actorId) {
      calls.push({ method: "startAuthorization", actorId });
      current = publicStatus({ phase: "pending", updatedBy: actorId, userCode: "WDJB-MJHT" });
      return current;
    },
    async getAuthorizationStatus() {
      calls.push({ method: "getAuthorizationStatus" });
      return current;
    },
    async cancelAuthorization(actorId) {
      calls.push({ method: "cancelAuthorization", actorId });
      current = publicStatus({ phase: "absent", configured: false, updatedBy: actorId, userCode: undefined });
      return current;
    },
    async disconnect(actorId) {
      calls.push({ method: "disconnect", actorId });
      current = publicStatus({
        phase: "absent",
        configured: false,
        updatedBy: actorId,
        userCode: undefined,
        verificationUrl: undefined,
        intervalSeconds: undefined,
        expiresAt: undefined,
      });
      return current;
    },
    async resolveAccessToken() {
      calls.push({ method: "resolveAccessToken" });
      return "access_token_must_never_leave_store";
    },
    async isConfigured() {
      calls.push({ method: "isConfigured" });
      return current.configured;
    },
  };
  return { store, calls };
}

function start(opts: {
  openaiCodexCredentials?: OpenAICodexCredentialStore;
  modelCredentialFetch?: typeof fetch;
  config?: Parameters<typeof testConfig>[0];
} = {}): {
  base: string;
  built: BuiltApp;
  close: () => Promise<void>;
} {
  const modelCredentialFetch =
    opts.modelCredentialFetch ?? (async () => new Response(null, { status: 200 }));
  const built = buildApp(
    testConfig({
      dataDir: mkdtempSync(join(tmpdir(), "openai-codex-device-route-")),
      ...opts.config,
    }),
    { modelCredentialFetch },
  );
  const server = createInsecureTestServer(built.app, {
    config: built.config,
    modelCredentials: built.modelCredentials,
    modelCredentialFetch,
    harnessId: opts.config?.harness ?? "pi",
    providerKeys: {
      anthropic: Boolean(opts.config?.anthropicApiKey),
      openai: Boolean(opts.config?.openaiApiKey),
      openrouter: Boolean(opts.config?.openrouterApiKey),
    },
    admin: built.admin,
    auditLog: built.auditLog,
    ...("openaiCodexCredentials" in opts
      ? { openaiCodexCredentials: opts.openaiCodexCredentials }
      : { openaiCodexCredentials: built.openaiCodexCredentials }),
  });
  server.listen(0);
  return {
    base: `http://localhost:${(server.address() as AddressInfo).port}`,
    built,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

test("admin device start/status/cancel/disconnect call the store and return public status", async () => {
  const { store, calls } = fakeStore();
  const srv = start({ openaiCodexCredentials: store });
  try {
    const started = await fetch(`${srv.base}${DEVICE}/start`, { method: "POST", headers: ADMIN, body: "{}" });
    assert.equal(started.status, 200);
    const startBody = (await started.json()) as OpenAICodexPublicStatus;
    assert.equal(startBody.provider, "openai-codex");
    assert.equal(startBody.phase, "pending");
    assert.equal(startBody.userCode, "WDJB-MJHT");
    assertNoPrivateFields(startBody);
    assert.deepEqual(calls.at(-1), { method: "startAuthorization", actorId: "admin-alice" });

    const status = await fetch(`${srv.base}${DEVICE}/status`, { headers: ADMIN });
    assert.equal(status.status, 200);
    const statusBody = (await status.json()) as OpenAICodexPublicStatus;
    assert.equal(statusBody.phase, "pending");
    assertNoPrivateFields(statusBody);
    assert.equal(calls.at(-1)?.method, "getAuthorizationStatus");

    const cancelled = await fetch(`${srv.base}${DEVICE}/cancel`, {
      method: "POST",
      headers: ADMIN,
      body: "{}",
    });
    assert.equal(cancelled.status, 200);
    assertNoPrivateFields(await cancelled.json());
    assert.deepEqual(calls.at(-1), { method: "cancelAuthorization", actorId: "admin-alice" });

    const disconnected = await fetch(`${srv.base}${BASE}`, { method: "DELETE", headers: ADMIN });
    assert.equal(disconnected.status, 200);
    assert.deepEqual(await disconnected.json(), { ok: true });
    assert.deepEqual(calls.at(-1), { method: "disconnect", actorId: "admin-alice" });
  } finally {
    await srv.close();
  }
});

test("non-admin callers are forbidden on every openai-codex device route", async () => {
  const { store, calls } = fakeStore();
  const srv = start({ openaiCodexCredentials: store });
  try {
    const requests: Array<Promise<Response>> = [
      fetch(`${srv.base}${DEVICE}/start`, { method: "POST", headers: NON_ADMIN, body: "{}" }),
      fetch(`${srv.base}${DEVICE}/status`, { headers: NON_ADMIN }),
      fetch(`${srv.base}${DEVICE}/cancel`, { method: "POST", headers: NON_ADMIN, body: "{}" }),
      fetch(`${srv.base}${BASE}`, { method: "DELETE", headers: NON_ADMIN }),
    ];
    const responses = await Promise.all(requests);
    for (const response of responses) {
      assert.equal(response.status, 403);
      assert.equal(((await response.json()) as { error: string }).error, "forbidden");
    }
    assert.equal(calls.length, 0);
  } finally {
    await srv.close();
  }
});

test("public responses never leak private oauth material", async () => {
  const { store } = fakeStore(
    publicStatus({
      phase: "connected",
      configured: true,
      userCode: undefined,
      verificationUrl: undefined,
    }),
  );
  const srv = start({ openaiCodexCredentials: store });
  try {
    for (const [method, path] of [
      ["POST", `${DEVICE}/start`],
      ["GET", `${DEVICE}/status`],
      ["POST", `${DEVICE}/cancel`],
    ] as const) {
      const response = await fetch(`${srv.base}${path}`, {
        method,
        headers: ADMIN,
        ...(method === "GET" ? {} : { body: "{}" }),
      });
      assert.equal(response.status, 200);
      assertNoPrivateFields(await response.json());
    }
    const deleted = await fetch(`${srv.base}${BASE}`, { method: "DELETE", headers: ADMIN });
    assert.equal(deleted.status, 200);
    assertNoPrivateFields(await deleted.json());
  } finally {
    await srv.close();
  }
});

test("missing openai-codex store returns a safe unavailable error", async () => {
  const srv = start({ openaiCodexCredentials: undefined });
  try {
    for (const [method, path] of [
      ["POST", `${DEVICE}/start`],
      ["GET", `${DEVICE}/status`],
      ["POST", `${DEVICE}/cancel`],
      ["DELETE", BASE],
    ] as const) {
      const response = await fetch(`${srv.base}${path}`, {
        method,
        headers: ADMIN,
        ...(method === "GET" || method === "DELETE" ? {} : { body: "{}" }),
      });
      assert.equal(response.status, 503);
      const body = (await response.json()) as { error: string };
      assert.ok(body.error === "not_configured" || body.error === "unavailable" || body.error === "disabled");
      assertNoPrivateFields(body);
    }
  } finally {
    await srv.close();
  }
});

test("PUT openai-codex with apiKey is rejected as oauth_required without validation fetch", async () => {
  let validationCalls = 0;
  const { store, calls } = fakeStore();
  const srv = start({
    openaiCodexCredentials: store,
    modelCredentialFetch: async () => {
      validationCalls += 1;
      return new Response(null, { status: 200 });
    },
  });
  try {
    const response = await fetch(`${srv.base}${BASE}`, {
      method: "PUT",
      headers: ADMIN,
      body: JSON.stringify({ apiKey: "sk-should-not-be-accepted" }),
    });
    assert.equal(response.status, 400);
    const body = (await response.json()) as { error: string };
    assert.equal(body.error, "oauth_required");
    assert.equal(validationCalls, 0);
    assert.equal(calls.length, 0);
    assert.equal(await srv.built.modelCredentials.resolve("openai"), null);
  } finally {
    await srv.close();
  }
});

test("anthropic openai and openrouter api-key routes remain unchanged", async () => {
  let openrouterUrl = "";
  const srv = start({
    openaiCodexCredentials: fakeStore().store,
    modelCredentialFetch: async (input) => {
      openrouterUrl = String(input);
      return new Response(null, { status: 200 });
    },
  });
  try {
    for (const provider of ["anthropic", "openai", "openrouter"] as const) {
      const saved = await fetch(`${srv.base}/v1/admin/model-providers/${provider}`, {
        method: "PUT",
        headers: ADMIN,
        body: JSON.stringify({ apiKey: `managed-${provider}-key` }),
      });
      assert.equal(saved.status, 200);
      assert.equal(await srv.built.modelCredentials.resolve(provider), `managed-${provider}-key`);
      const removed = await fetch(`${srv.base}/v1/admin/model-providers/${provider}`, {
        method: "DELETE",
        headers: ADMIN,
      });
      assert.equal(removed.status, 200);
      assert.equal(await srv.built.modelCredentials.resolve(provider), null);
    }
    assert.equal(openrouterUrl, "https://openrouter.ai/api/v1/key");
  } finally {
    await srv.close();
  }
});

test("composition root wires openai-codex credentials through a durable artifact map", async () => {
  const wiringSource = readFileSync(new URL("../src/wiring.ts", import.meta.url), "utf8");
  assert.match(wiringSource, /artifactMap\(["']openai_codex_oauth["']\)/);
  assert.match(wiringSource, /createOpenAICodexCredentialStore/);
  assert.match(
    wiringSource,
    /const advisoryLock: AdvisoryLock = pgArtifactMap[\s\S]*?createOpenAICodexCredentialStore\(\{[\s\S]*?advisoryLock,/,
  );
  assert.doesNotMatch(
    wiringSource,
    /openaiCodexCredentials\s*=\s*new\s+Map|openai_codex_oauth[^\n]*new\s+Map/,
  );

  const srv = start();
  try {
    assert.ok(srv.built.openaiCodexCredentials);
    const status = await srv.built.openaiCodexCredentials.getAuthorizationStatus();
    assert.equal(status.provider, "openai-codex");
    assert.equal(status.phase, "absent");
    assertNoPrivateFields(status);
  } finally {
    await srv.close();
  }
});
