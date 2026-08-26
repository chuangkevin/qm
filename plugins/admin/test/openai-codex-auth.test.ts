import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";
import vm from "node:vm";

const html = readFileSync(new URL("../public/index.html", import.meta.url), "utf8");

type El = {
  textContent: string;
  className: string;
  disabled: boolean;
  classList: {
    toggle: (cls: string, on?: boolean) => void;
    contains: (cls: string) => boolean;
  };
  setAttribute: (name: string, value: string) => void;
  getAttribute: (name: string) => string | null;
  click: () => void | Promise<void>;
  onclick: ((ev?: unknown) => unknown) | null;
  hidden?: boolean;
};

function extractOpenAICodexAuthSource(): string {
  const start = html.indexOf("let openaiCodexPollTimer = null;");
  const end = html.indexOf("function onboardingBadge(");
  assert.ok(start >= 0 && end > start, "openai-codex auth block missing");
  return html.slice(start, end);
}

function extractOpenAICodexHandlerSource(): string {
  const start = html.indexOf('$("openai-codex-signin").onclick');
  const end = html.indexOf('$("onboarding-model-save").onclick');
  assert.ok(start >= 0 && end > start, "openai-codex handlers missing");
  return html.slice(start, end);
}

function createOpenAICodexAuthHarness(opts: {
  apiImpl?: (method: string, path: string, body?: unknown) => Promise<{ ok: boolean; data?: unknown }>;
  installHandlers?: boolean;
  confirmImpl?: () => boolean;
}) {
  const attrs = new Map<string, Map<string, string>>();
  const elements = new Map<string, El>();
  const ensure = (id: string): El => {
    let el = elements.get(id);
    if (el) return el;
    const store = new Map<string, string>();
    attrs.set(id, store);
    const classes = new Set<string>();
    el = {
      textContent: "",
      className: "",
      disabled: false,
      onclick: null,
      classList: {
        toggle(cls: string, on?: boolean) {
          const should = on === undefined ? !classes.has(cls) : Boolean(on);
          if (should) classes.add(cls);
          else classes.delete(cls);
          el!.className = [...classes].join(" ");
        },
        contains(cls: string) {
          return classes.has(cls);
        },
      },
      setAttribute(name: string, value: string) {
        store.set(name, value);
      },
      getAttribute(name: string) {
        return store.has(name) ? store.get(name)! : null;
      },
      click() {
        const handler = el!.onclick;
        if (handler) return handler();
      },
    };
    elements.set(id, el);
    return el;
  };
  for (const id of [
    "openai-codex-verification-url",
    "openai-codex-badge",
    "openai-codex-summary",
    "openai-codex-pending",
    "openai-codex-signin",
    "openai-codex-copy-code",
    "openai-codex-cancel",
    "openai-codex-reconnect",
    "openai-codex-disconnect",
    "openai-codex-user-code",
    "st-openai-codex",
  ]) {
    ensure(id);
  }

  type Timer = { fn: () => unknown; due: number };
  let now = 0;
  let nextTimerId = 1;
  const timers = new Map<number, Timer>();
  const statusLog: { id: string; msg: string; kind: string; sticky: boolean }[] = [];
  let apiCalls = 0;
  let pendingApi: {
    resolve: (v: { ok: boolean; data?: unknown }) => void;
    reject: (e: unknown) => void;
  } | null = null;

  const apiImpl =
    opts.apiImpl ??
    (async () => {
      apiCalls += 1;
      return new Promise<{ ok: boolean; data?: unknown }>((resolve, reject) => {
        pendingApi = { resolve, reject };
      });
    });

  const context = vm.createContext({
    Number,
    String,
    Boolean,
    Math,
    console,
    __openaiCodexAuth: null as null | Record<string, unknown>,
    confirm: opts.confirmImpl ?? (() => true),
    async copyText() {
      return true;
    },
    setTimeout(fn: () => unknown, ms: number) {
      const id = nextTimerId++;
      timers.set(id, { fn, due: now + ms });
      return id;
    },
    clearTimeout(id: number) {
      timers.delete(id);
    },
    $(id: string) {
      return ensure(id);
    },
    async api(method: string, path: string, body?: unknown) {
      return apiImpl(method, path, body);
    },
    setStatus(id: string, msg: string, kind: string, sticky = false) {
      statusLog.push({ id, msg, kind, sticky: Boolean(sticky) });
      const el = ensure(id);
      el.textContent = msg;
      el.className = "status " + (kind || "");
    },
  });

  const handlerSource = opts.installHandlers ? extractOpenAICodexHandlerSource() : "";
  vm.runInContext(
    `${extractOpenAICodexAuthSource()}
${handlerSource}
__openaiCodexAuth = {
  get openaiCodexUserCode() { return openaiCodexUserCode; },
  get openaiCodexPollGeneration() { return openaiCodexPollGeneration; },
  renderOpenAICodexStatus,
  loadOpenAICodexAuth,
  setOpenAICodexVerificationLink,
  scheduleOpenAICodexPoll,
  clearOpenAICodexPoll,
  invalidateOpenAICodexPoll,
};`,
    context,
  );

  const api = context.__openaiCodexAuth as {
    openaiCodexUserCode: string;
    openaiCodexPollGeneration: number;
    renderOpenAICodexStatus: (status: Record<string, unknown>) => void;
    loadOpenAICodexAuth: () => Promise<void>;
    setOpenAICodexVerificationLink: (url: unknown) => void;
    scheduleOpenAICodexPoll: (intervalSeconds: unknown) => void;
    clearOpenAICodexPoll: () => void;
    invalidateOpenAICodexPoll: () => void;
  };
  assert.ok(api, "auth helpers failed to export from vm");

  return {
    elements,
    attrs,
    statusLog,
    get apiCalls() {
      return apiCalls;
    },
    get timerCount() {
      return timers.size;
    },
    get openaiCodexUserCode() {
      return api.openaiCodexUserCode;
    },
    get openaiCodexPollGeneration() {
      return api.openaiCodexPollGeneration;
    },
    renderOpenAICodexStatus: api.renderOpenAICodexStatus,
    loadOpenAICodexAuth: api.loadOpenAICodexAuth,
    setOpenAICodexVerificationLink: api.setOpenAICodexVerificationLink,
    scheduleOpenAICodexPoll: api.scheduleOpenAICodexPoll,
    clearOpenAICodexPoll: api.clearOpenAICodexPoll,
    invalidateOpenAICodexPoll: api.invalidateOpenAICodexPoll,
    beginAdvance(ms: number) {
      now += ms;
      const running: Promise<unknown>[] = [];
      for (;;) {
        const due = [...timers.entries()].filter(([, t]) => t.due <= now);
        if (!due.length) break;
        for (const [id, t] of due) {
          timers.delete(id);
          running.push(Promise.resolve(t.fn()));
        }
      }
      return Promise.all(running);
    },
    async advance(ms: number) {
      await this.beginAdvance(ms);
    },
    resolveApi(value: { ok: boolean; data?: unknown }) {
      assert.ok(pendingApi, "expected in-flight api");
      const p = pendingApi;
      pendingApi = null;
      p.resolve(value);
    },
    rejectApi(err: unknown) {
      assert.ok(pendingApi, "expected in-flight api");
      const p = pendingApi;
      pendingApi = null;
      p.reject(err);
    },
  };
}

const calls: { method: string; url: string; actor: string | null; signed: boolean; body: string }[] = [];
const core = createServer((req: IncomingMessage, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    calls.push({
      method: req.method ?? "",
      url: req.url ?? "",
      actor: (req.headers["x-admin-actor"] as string) ?? null,
      signed: Boolean(req.headers["x-timestamp"] && req.headers["x-signature"]),
      body,
    });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        provider: "openai-codex",
        phase: "pending",
        configured: false,
        verificationUrl: "https://auth.openai.com/codex/device",
        userCode: "WDJB-MJHT",
        intervalSeconds: 5,
      }),
    );
  });
});
await new Promise<void>((r) => core.listen(0, r));
const corePort = (core.address() as AddressInfo).port;

process.env.CORE_API_URL = `http://localhost:${corePort}`;
process.env.CORE_SIGNING_SECRET = "admin-openai-codex-proxy-secret";
process.env.NODE_ENV = "test";
process.env.ALLOW_UNSIGNED_TEST_IDENTITY = "1";

const { server } = await import("../src/index.ts");
await new Promise<void>((r) => server.listen(0, r));
const base = `http://localhost:${(server.address() as AddressInfo).port}`;
test.after(() => {
  server.close();
  if (core.listening) core.close();
});

const ADMIN = "admin=U-admin";
const DEVICE = "/api/model-providers/openai-codex/device";
const CORE_DEVICE = "/v1/admin/model-providers/openai-codex/device";

test("POST device/start forwards signed + attributed to core", async () => {
  const r = await fetch(`${base}${DEVICE}/start`, {
    method: "POST",
    headers: { cookie: ADMIN, "content-type": "application/json" },
    body: "{}",
  });
  assert.equal(r.status, 200);
  const c = calls.at(-1)!;
  assert.equal(c.method, "POST");
  assert.equal(c.url, `${CORE_DEVICE}/start`);
  assert.equal(c.actor, "U-admin@acme");
  assert.equal(c.signed, true);
});

test("GET device/status forwards signed + attributed to core", async () => {
  const r = await fetch(`${base}${DEVICE}/status`, { headers: { cookie: ADMIN } });
  assert.equal(r.status, 200);
  const c = calls.at(-1)!;
  assert.equal(c.method, "GET");
  assert.equal(c.url, `${CORE_DEVICE}/status`);
  assert.equal(c.actor, "U-admin@acme");
  assert.equal(c.signed, true);
});

test("POST device/cancel forwards signed + attributed to core", async () => {
  const r = await fetch(`${base}${DEVICE}/cancel`, {
    method: "POST",
    headers: { cookie: ADMIN, "content-type": "application/json" },
    body: "{}",
  });
  assert.equal(r.status, 200);
  const c = calls.at(-1)!;
  assert.equal(c.method, "POST");
  assert.equal(c.url, `${CORE_DEVICE}/cancel`);
  assert.equal(c.actor, "U-admin@acme");
  assert.equal(c.signed, true);
});

test("DELETE openai-codex disconnect forwards signed + attributed to core", async () => {
  const r = await fetch(`${base}/api/model-providers/openai-codex`, {
    method: "DELETE",
    headers: { cookie: ADMIN },
  });
  assert.equal(r.status, 200);
  const c = calls.at(-1)!;
  assert.equal(c.method, "DELETE");
  assert.equal(c.url, "/v1/admin/model-providers/openai-codex");
  assert.equal(c.actor, "U-admin@acme");
  assert.equal(c.signed, true);
});

test("adjacent model-provider proxy routes still work", async () => {
  const get = await fetch(`${base}/api/model-providers`, { headers: { cookie: ADMIN } });
  assert.equal(get.status, 200);
  assert.equal(calls.at(-1)!.method, "GET");
  assert.equal(calls.at(-1)!.url, "/v1/admin/model-providers");
  assert.equal(calls.at(-1)!.actor, "U-admin@acme");
  assert.equal(calls.at(-1)!.signed, true);

  const put = await fetch(`${base}/api/model-providers/openai`, {
    method: "PUT",
    headers: { cookie: ADMIN, "content-type": "application/json" },
    body: JSON.stringify({ apiKey: "sk-test" }),
  });
  assert.equal(put.status, 200);
  assert.equal(calls.at(-1)!.method, "PUT");
  assert.equal(calls.at(-1)!.url, "/v1/admin/model-providers/openai");
  assert.equal(calls.at(-1)!.actor, "U-admin@acme");
  assert.equal(calls.at(-1)!.signed, true);

  const del = await fetch(`${base}/api/model-providers/openrouter`, {
    method: "DELETE",
    headers: { cookie: ADMIN },
  });
  assert.equal(del.status, 200);
  assert.equal(calls.at(-1)!.method, "DELETE");
  assert.equal(calls.at(-1)!.url, "/v1/admin/model-providers/openrouter");
});

test("non-allowlisted nested openai-codex paths and methods are rejected", async () => {
  const before = calls.length;
  assert.equal(
    (
      await fetch(`${base}${DEVICE}/poll`, {
        method: "POST",
        headers: { cookie: ADMIN, "content-type": "application/json" },
        body: "{}",
      })
    ).status,
    404,
  );
  assert.equal(
    (
      await fetch(`${base}/api/model-providers/openai-codex/device`, {
        method: "POST",
        headers: { cookie: ADMIN, "content-type": "application/json" },
        body: "{}",
      })
    ).status,
    404,
  );
  assert.equal(
    (
      await fetch(`${base}${DEVICE}/start`, {
        method: "PUT",
        headers: { cookie: ADMIN, "content-type": "application/json" },
        body: "{}",
      })
    ).status,
    404,
  );
  assert.equal(
    (
      await fetch(`${base}/api/model-providers/openai-codex/extra`, {
        method: "DELETE",
        headers: { cookie: ADMIN },
      })
    ).status,
    404,
  );
  assert.equal(calls.length, before, "rejected nested paths never hop to core");
});

test("device auth routes require a signed-in cookie", async () => {
  const before = calls.length;
  assert.equal((await fetch(`${base}${DEVICE}/start`, { method: "POST", body: "{}" })).status, 401);
  assert.equal((await fetch(`${base}${DEVICE}/status`)).status, 401);
  assert.equal((await fetch(`${base}${DEVICE}/cancel`, { method: "POST", body: "{}" })).status, 401);
  assert.equal((await fetch(`${base}/api/model-providers/openai-codex`, { method: "DELETE" })).status, 401);
  assert.equal(calls.length, before);
});

test("admin HTML exposes ChatGPT/Codex browser-auth card without apiKey or tokens", () => {
  assert.match(html, /id="card-openai-codex"/);
  assert.match(html, /ChatGPT \/ Codex \(browser\)/);
  assert.doesNotMatch(html, /<h2>OpenAI \/ ChatGPT/);
  assert.match(html, /ChatGPT\/Codex browser/);
  assert.match(html, /Sign in with browser/);
  assert.match(html, /\/api\/model-providers\/openai-codex\/device\/start/);
  assert.match(html, /\/api\/model-providers\/openai-codex\/device\/status/);
  assert.match(html, /\/api\/model-providers\/openai-codex\/device\/cancel/);
  assert.match(html, /api\("DELETE", "\/api\/model-providers\/openai-codex"/);
  assert.match(html, /id="openai-codex-user-code"/);
  assert.match(html, /id="openai-codex-verification-url"/);
  assert.match(html, /id="openai-codex-copy-code"/);
  assert.match(html, /id="openai-codex-cancel"/);
  assert.match(html, /id="openai-codex-disconnect"/);
  assert.match(html, /id="openai-codex-reconnect"/);
  assert.match(html, /id="openai-codex-badge"/);
  assert.doesNotMatch(html, /api\("PUT", "\/api\/model-providers\/openai-codex"/);
  const openaiCodexCard = html.match(/id="card-openai-codex"[\s\S]*?<\/section>/)?.[0] ?? "";
  assert.ok(openaiCodexCard, "openai-codex card markup exists");
  assert.doesNotMatch(openaiCodexCard, /type="password"|apiKey|name="apiKey"/);
  assert.doesNotMatch(html, /api\("POST", "\/api\/model-providers\/openai-codex\/device\/start"[^)]*apiKey/);
  assert.doesNotMatch(html, /access_token|refresh_token|accessToken|refreshToken/);
});

test("browser auth uses safe DOM writes, external link attrs, and chained polling cleanup", () => {
  assert.match(html, /target="_blank"/);
  assert.match(html, /rel="noopener noreferrer"/);
  assert.match(html, /openai-codex-verification-url[\s\S]{0,400}href/);
  assert.match(html, /\.textContent\s*=/);
  assert.doesNotMatch(html, /openai-codex[\s\S]{0,800}innerHTML\s*=/);
  assert.match(html, /intervalSeconds/);
  assert.match(html, /setTimeout\(/);
  assert.match(html, /clearTimeout\(/);
  assert.match(html, /openaiCodexPollTimer/);
  assert.match(html, /phase === "pending"|phase === "slow_down"|=== "pending" \|\|[\s\S]*slow_down/);
  assert.match(html, /"connected"/);
  assert.match(html, /"denied"/);
  assert.match(html, /"expired"/);
  assert.match(html, /"reconnect_required"/);
  assert.match(html, /slow_down/);
});

test("openai-codex auth CSS covers tablet/phone RWD without page-wide overflow", () => {
  assert.match(html, /@media \(max-width: 1023px\)/);
  assert.match(html, /@media \(max-width: 767px\)/);
  assert.match(html, /\.openai-codex-auth[\s\S]{0,600}overflow-x:\s*auto|overflow-wrap:\s*anywhere|word-break:\s*break-all/);
  assert.match(html, /\.openai-codex-actions[\s\S]{0,400}flex-wrap:\s*wrap/);
  assert.match(html, /\.openai-codex-actions[\s\S]{0,500}min-height:\s*44px/);
  assert.doesNotMatch(html, /\.openai-codex-actions[\s\S]{0,400}:hover[\s\S]{0,200}opacity:\s*0/);
  assert.doesNotMatch(html, /\.openai-codex[\s\S]{0,300}visibility:\s*hidden/);
});

test("each auth phase has a visible operator contract in the shell", () => {
  for (const phase of ["absent", "pending", "slow_down", "connected", "denied", "expired", "reconnect_required"]) {
    assert.match(html, new RegExp(phase));
  }
  assert.match(html, /Waiting for browser|Authorize in browser|Authorization pending/i);
  assert.match(html, /Connected|Signed in/i);
  assert.match(html, /Temporarily unavailable|temporarily unavailable/i);
  assert.match(html, /Denied|expired|Reconnect|Try again/i);
  assert.match(html, /Copy code|Copy/);
  assert.match(html, /Cancel/);
  assert.match(html, /Disconnect/);
  assert.match(html, /Reconnect|Sign in again|Try again/);
});

test("status poll !res.ok keeps pending poll alive at last interval", async () => {
  let calls = 0;
  const h = createOpenAICodexAuthHarness({
    apiImpl: async () => {
      calls += 1;
      return { ok: false, data: { message: "upstream 502" } };
    },
  });
  h.renderOpenAICodexStatus({
    phase: "pending",
    userCode: "WDJB-MJHT",
    verificationUrl: "https://auth.openai.com/codex/device",
    intervalSeconds: 5,
  });
  assert.equal(h.timerCount, 1);
  await h.advance(5000);
  assert.equal(calls, 1);
  assert.equal(h.timerCount, 1, "first status failure must schedule a second timer");
  assert.ok(h.statusLog.some((s) => s.sticky && /could not be refreshed/i.test(s.msg)));
  await h.advance(5000);
  assert.equal(calls, 2);
  assert.equal(h.timerCount, 1);
});

test("status poll throw also reschedules without accelerating", async () => {
  let calls = 0;
  const h = createOpenAICodexAuthHarness({
    apiImpl: async () => {
      calls += 1;
      throw new Error("network down");
    },
  });
  h.scheduleOpenAICodexPoll(5);
  await h.advance(5000);
  assert.equal(calls, 1);
  assert.equal(h.timerCount, 1, "throw must reschedule");
  await h.advance(4999);
  assert.equal(calls, 1, "must not fire early");
  await h.advance(1);
  assert.equal(calls, 2);
});

test("cancel/terminal invalidate stops in-flight poll from rescheduling", async () => {
  const h = createOpenAICodexAuthHarness({});
  h.renderOpenAICodexStatus({
    phase: "pending",
    userCode: "ABCD-EFGH",
    verificationUrl: "https://auth.openai.com/codex/device",
    intervalSeconds: 5,
  });
  assert.equal(h.timerCount, 1);
  const fire = h.beginAdvance(5000);
  await Promise.resolve();
  h.invalidateOpenAICodexPoll();
  h.renderOpenAICodexStatus({ phase: "absent", provider: "openai-codex", configured: false });
  h.resolveApi({ ok: false });
  await fire;
  assert.equal(h.timerCount, 0, "invalidated in-flight failure must not reschedule");
  assert.equal(h.openaiCodexUserCode, "");
});

test("verification link allowlists only the official device URL", () => {
  const h = createOpenAICodexAuthHarness({
    apiImpl: async () => ({ ok: true, data: {} }),
  });
  const href = () => h.attrs.get("openai-codex-verification-url")!.get("href");
  const label = () => h.elements.get("openai-codex-verification-url")!.textContent;

  h.setOpenAICodexVerificationLink("https://evil.example");
  assert.equal(href(), "#");
  assert.equal(label(), "Open authorization page ↗");

  h.setOpenAICodexVerificationLink("https://auth.openai.com.evil/codex/device");
  assert.equal(href(), "#");

  h.setOpenAICodexVerificationLink("https://auth.openai.com/codex/device/extra");
  assert.equal(href(), "#");

  h.setOpenAICodexVerificationLink("http://auth.openai.com/codex/device");
  assert.equal(href(), "#");

  h.setOpenAICodexVerificationLink("https://auth.openai.com/codex/device");
  assert.equal(href(), "https://auth.openai.com/codex/device");
  assert.equal(label(), "https://auth.openai.com/codex/device");

  h.setOpenAICodexVerificationLink("https://auth.openai.com/codex/device/");
  assert.equal(href(), "https://auth.openai.com/codex/device");
});

test("leaving pending clears user code and verification href", () => {
  const h = createOpenAICodexAuthHarness({
    apiImpl: async () => ({ ok: true, data: {} }),
  });
  for (const phase of ["connected", "denied", "expired", "reconnect_required", "absent"]) {
    h.renderOpenAICodexStatus({
      phase: "pending",
      userCode: "STALE-CODE",
      verificationUrl: "https://auth.openai.com/codex/device",
      intervalSeconds: 5,
    });
    assert.equal(h.openaiCodexUserCode, "STALE-CODE");
    assert.equal(h.elements.get("openai-codex-user-code")!.textContent, "STALE-CODE");
    assert.equal(h.attrs.get("openai-codex-verification-url")!.get("href"), "https://auth.openai.com/codex/device");

    h.renderOpenAICodexStatus({ phase, provider: "openai-codex", configured: phase === "connected" });
    assert.equal(h.openaiCodexUserCode, "", `phase ${phase} must clear openaiCodexUserCode`);
    assert.equal(h.elements.get("openai-codex-user-code")!.textContent, "");
    assert.equal(h.attrs.get("openai-codex-verification-url")!.get("href"), "#");
    assert.equal(h.timerCount, 0);
  }
});

test("connected with configured false shows degraded controls, not Connected", () => {
  const h = createOpenAICodexAuthHarness({
    apiImpl: async () => ({ ok: true, data: {} }),
  });
  h.renderOpenAICodexStatus({
    phase: "connected",
    provider: "openai-codex",
    configured: true,
  });
  assert.equal(h.elements.get("openai-codex-badge")!.textContent, "Connected");
  assert.ok(h.elements.get("openai-codex-signin")!.classList.contains("hidden"));
  assert.ok(h.elements.get("openai-codex-reconnect")!.classList.contains("hidden"));
  assert.equal(h.elements.get("openai-codex-disconnect")!.classList.contains("hidden"), false);

  h.renderOpenAICodexStatus({
    phase: "connected",
    provider: "openai-codex",
    configured: false,
  });
  assert.equal(h.elements.get("openai-codex-badge")!.textContent, "Temporarily unavailable");
  assert.match(h.elements.get("openai-codex-summary")!.textContent, /temporarily unavailable/i);
  assert.doesNotMatch(h.elements.get("openai-codex-badge")!.textContent, /Connected/i);
  assert.doesNotMatch(h.elements.get("openai-codex-summary")!.textContent, /\bConnected\b/);
  assert.ok(h.elements.get("openai-codex-signin")!.classList.contains("hidden"));
  assert.equal(h.elements.get("openai-codex-reconnect")!.classList.contains("hidden"), false);
  assert.equal(h.elements.get("openai-codex-disconnect")!.classList.contains("hidden"), false);
  assert.ok(h.statusLog.some((s) => s.sticky && /temporarily unavailable/i.test(s.msg)));
  assert.ok(!h.statusLog.some((s) => /apiKey|access_token|refresh_token|sk-/i.test(s.msg)));
  assert.equal(h.timerCount, 0);
});

test("loadOpenAICodexAuth fetch throw recovers with safe sticky status", async () => {
  const h = createOpenAICodexAuthHarness({
    apiImpl: async () => {
      throw new Error("network down");
    },
  });
  const genBefore = h.openaiCodexPollGeneration;
  await assert.doesNotReject(() => h.loadOpenAICodexAuth());
  assert.equal(h.elements.get("openai-codex-badge")!.textContent, "Not connected");
  assert.ok(h.statusLog.some((s) => s.sticky && /could not be loaded/i.test(s.msg)));
  assert.ok(!h.statusLog.some((s) => /network down/i.test(s.msg)));
  assert.equal(h.openaiCodexPollGeneration, genBefore + 1);
  assert.equal(h.timerCount, 0);
});

test("Sign in fetch throw re-enables button with safe sticky status", async () => {
  const h = createOpenAICodexAuthHarness({
    apiImpl: async () => {
      throw new Error("fetch failed: ECONNREFUSED");
    },
    installHandlers: true,
  });
  const signin = h.elements.get("openai-codex-signin")!;
  assert.ok(signin.onclick, "signin handler installed");
  const genBefore = h.openaiCodexPollGeneration;
  await assert.doesNotReject(async () => {
    await signin.onclick!();
  });
  assert.equal(signin.disabled, false);
  assert.ok(h.statusLog.some((s) => s.sticky && /Could not start browser authorization/i.test(s.msg)));
  assert.ok(!h.statusLog.some((s) => /ECONNREFUSED|fetch failed/i.test(s.msg)));
  assert.equal(h.openaiCodexPollGeneration, genBefore);
  assert.equal(h.timerCount, 0);
});

test("Cancel and Disconnect fetch throw re-enable buttons without restarting poll", async () => {
  const h = createOpenAICodexAuthHarness({
    apiImpl: async () => {
      throw new Error("socket hang up");
    },
    installHandlers: true,
  });
  h.renderOpenAICodexStatus({
    phase: "pending",
    userCode: "ABCD-EFGH",
    verificationUrl: "https://auth.openai.com/codex/device",
    intervalSeconds: 5,
  });
  assert.equal(h.timerCount, 1);
  const genAfterPending = h.openaiCodexPollGeneration;

  const cancel = h.elements.get("openai-codex-cancel")!;
  await assert.doesNotReject(async () => {
    await cancel.onclick!();
  });
  assert.equal(cancel.disabled, false);
  assert.ok(h.statusLog.some((s) => s.sticky && /Could not cancel authorization/i.test(s.msg)));
  assert.ok(!h.statusLog.some((s) => /socket hang up/i.test(s.msg)));
  assert.equal(h.openaiCodexPollGeneration, genAfterPending + 1);
  assert.equal(h.timerCount, 0);

  const disconnect = h.elements.get("openai-codex-disconnect")!;
  const genBeforeDisconnect = h.openaiCodexPollGeneration;
  await assert.doesNotReject(async () => {
    await disconnect.onclick!();
  });
  assert.equal(disconnect.disabled, false);
  assert.ok(h.statusLog.some((s) => s.sticky && /Could not disconnect/i.test(s.msg)));
  assert.equal(h.openaiCodexPollGeneration, genBeforeDisconnect + 1);
  assert.equal(h.timerCount, 0);
});