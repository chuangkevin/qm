import "./support/auto-fake-sprites.ts";

import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { stream } from "@earendil-works/pi-ai/api/openai-codex-responses";
import { createMemoryMap } from "../src/persistence/durable-map.ts";
import { createCustomProviderStore } from "../src/model/custom-provider-store.ts";
import { createModelCredentialStore } from "../src/model/model-credential-store.ts";
import { modelServiceable, resolveModel } from "../src/model/pi-models.ts";
import { buildApp, resolveModelProviderKeys } from "../src/wiring.ts";
import { testConfig } from "./support/test-config.ts";

const KEY_MATERIAL = "test-openai-codex-runtime-key-aaaaaaaa";

function jwtWithAccount(accountId: string): string {
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      exp: Math.floor(Date.now() / 1000) + 3600,
      "https://api.openai.com/auth": { chatgpt_account_id: accountId },
    }),
  ).toString("base64url");
  return `${header}.${payload}.sig`;
}

test("availability merges openai-codex OAuth configured without accepting an API key", async () => {
  let configured = false;
  const store = createModelCredentialStore({
    backing: createMemoryMap(),
    keyMaterial: KEY_MATERIAL,
    fallback: { openai: "sk-platform-must-not-imply-codex" },
    openaiCodexConfigured: async () => configured,
  });

  assert.deepEqual(await store.availability(), {
    anthropic: false,
    openai: true,
    openrouter: false,
    "openai-codex": false,
  });
  assert.equal(modelServiceable("openai-codex/gpt-5.6-sol", await store.availability()), false);
  assert.equal(modelServiceable("gpt-5.6-sol", await store.availability()), true);

  configured = true;
  assert.equal((await store.availability())["openai-codex"], true);
  assert.equal(modelServiceable("openai-codex/gpt-5.6-sol", await store.availability()), true);
  assert.equal(modelServiceable("gpt-5.6-sol", await store.availability()), true);

  await assert.rejects(() => store.set("openai-codex" as never, "sk-should-fail", "admin"), /Unsupported model provider/);
});

test("resolveModelProviderKeys injects openai-codex only when resolveAccessToken returns a token", async () => {
  let token: string | null = "codex-access-token";
  let resolveCalls = 0;
  const modelCredentials = createModelCredentialStore({
    backing: createMemoryMap(),
    keyMaterial: KEY_MATERIAL,
    fallback: { openai: "sk-platform-key" },
  });
  const customProviders = createCustomProviderStore({
    backing: createMemoryMap(),
    keyMaterial: KEY_MATERIAL,
  });
  const openaiCodexCredentials = {
    async resolveAccessToken() {
      resolveCalls += 1;
      return token;
    },
  };

  const withToken = await resolveModelProviderKeys({
    modelCredentials,
    openaiCodexCredentials,
    customProviders,
  });
  assert.equal(resolveCalls, 1);
  assert.equal(withToken["openai-codex"], "codex-access-token");
  assert.equal(withToken.openai, "sk-platform-key");
  assert.notEqual(withToken.openai, withToken["openai-codex"]);

  token = null;
  const withoutToken = await resolveModelProviderKeys({
    modelCredentials,
    openaiCodexCredentials,
    customProviders,
  });
  assert.equal(resolveCalls, 2);
  assert.equal("openai-codex" in withoutToken, false);
  assert.equal(withoutToken.openai, "sk-platform-key");
});

test("composition root wires availability from openaiCodexCredentials.isConfigured", async () => {
  const built = buildApp(
    testConfig({
      dataDir: mkdtempSync(join(tmpdir(), "openai-codex-runtime-")),
      openaiApiKey: "sk-platform-only",
    }),
  );
  try {
    let configuredCalls = 0;
    const original = built.openaiCodexCredentials.isConfigured.bind(built.openaiCodexCredentials);
    built.openaiCodexCredentials.isConfigured = async () => {
      configuredCalls += 1;
      return true;
    };
    const availability = await built.modelCredentials.availability();
    assert.equal(availability.openai, true);
    assert.equal(availability["openai-codex"], true);
    assert.ok(configuredCalls >= 1);
    built.openaiCodexCredentials.isConfigured = original;
  } finally {
    await built.runtime.releaseInFlightRuns();
  }
});

test("pinned pi-ai openai-codex-responses public seam sends ChatGPT URL and SSE headers", async () => {
  const model = resolveModel("openai-codex/gpt-5.6-sol");
  assert.ok(model);
  assert.equal(model.provider, "openai-codex");
  assert.equal(model.api, "openai-codex-responses");
  assert.equal(model.id, "gpt-5.6-sol");
  assert.equal(model.baseUrl, "https://chatgpt.com/backend-api");

  const token = jwtWithAccount("acct-test");
  const realFetch = globalThis.fetch;
  let captured: { url: string; headers: Headers } | undefined;
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    captured = { url: String(url), headers: new Headers(init?.headers) };
    return new Response("event: response.completed\ndata: {}\n\n", {
      status: 200,
      headers: { "content-type": "text/event-stream" },
    });
  }) as typeof globalThis.fetch;
  try {
    const events = stream(
      model as Parameters<typeof stream>[0],
      { messages: [{ role: "user", content: "hi", timestamp: Date.now() }] },
      { apiKey: token, transport: "sse" },
    );
    for await (const _event of events) {
    }
    assert.ok(captured);
    assert.equal(captured.url, "https://chatgpt.com/backend-api/codex/responses");
    assert.equal(captured.headers.get("authorization"), `Bearer ${token}`);
    assert.equal(captured.headers.get("chatgpt-account-id"), "acct-test");
    assert.equal(captured.headers.get("openai-beta"), "responses=experimental");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("web turn fails closed on openai-codex when managed availability is false before pi transport", async () => {
  const built = buildApp(
    testConfig({
      dataDir: mkdtempSync(join(tmpdir(), "openai-codex-fail-closed-")),
      harness: "pi",
      openaiApiKey: "sk-platform-only",
    }),
  );
  const realFetch = globalThis.fetch;
  let chatgptTransportHits = 0;
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    const target = String(url);
    if (target.includes("chatgpt.com") || target.includes("auth.openai.com")) {
      chatgptTransportHits += 1;
      throw new Error(`unexpected openai-codex transport fetch: ${target}`);
    }
    return realFetch(url, init);
  }) as typeof globalThis.fetch;
  try {
    built.config.setApprovedHarnesses(["pi"]);
    await built.config.setRuntimeSelectionLatest("org:default-org", {
      harnessId: "pi",
      modelId: "openai-codex/gpt-5.6-sol",
    });
    built.openaiCodexCredentials.isConfigured = async () => false;
    assert.equal((await built.modelCredentials.availability())["openai-codex"], false);
    assert.equal(modelServiceable("openai-codex/gpt-5.6-sol", await built.modelCredentials.availability()), false);

    const turn = await built.app.turn({
      surface: "web",
      actor: { externalId: "alice" },
      conversation: { kind: "dm", threadRef: "web:alice:codex-fail-closed" },
      text: "hello",
      async: true,
    });
    assert.equal(turn.status, "refused");
    assert.match(turn.reason ?? "", /provider isn't configured|isn't available/i);
    assert.equal(chatgptTransportHits, 0);
  } finally {
    globalThis.fetch = realFetch;
    await built.runtime.releaseInFlightRuns();
  }
});
