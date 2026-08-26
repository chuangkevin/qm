import type {
  OpenAICodexCredentialStore,
  OpenAICodexPublicStatus,
} from "../../../model/openai-codex-credential-store.ts";
import { sendJson } from "../../http.ts";
import type { ApiCtx } from "../route.ts";
import { audit, authorizeAdmin, orgScope } from "../shared.ts";

async function actor(ctx: ApiCtx) {
  return authorizeAdmin(ctx, orgScope(ctx.deps));
}

function storeOrUnavailable(ctx: ApiCtx): OpenAICodexCredentialStore | null {
  if (ctx.deps.openaiCodexCredentials) return ctx.deps.openaiCodexCredentials;
  sendJson(ctx.res, 503, {
    error: "not_configured",
    message: "openai-codex oauth store is not wired",
  });
  return null;
}

function sendStatus(ctx: ApiCtx, status: OpenAICodexPublicStatus): void {
  sendJson(ctx.res, 200, status);
}

export async function startOpenAICodexDevice(ctx: ApiCtx): Promise<void> {
  const authorized = await actor(ctx);
  if (!authorized) return;
  const store = storeOrUnavailable(ctx);
  if (!store) return;
  const status = await store.startAuthorization(authorized.id);
  audit(ctx.deps, {
    principalId: authorized.id,
    action: "openai-codex.start",
    resource: "openai-codex",
    scopeLabel: orgScope(ctx.deps),
  });
  return sendStatus(ctx, status);
}

export async function getOpenAICodexDeviceStatus(ctx: ApiCtx): Promise<void> {
  const authorized = await actor(ctx);
  if (!authorized) return;
  const store = storeOrUnavailable(ctx);
  if (!store) return;
  return sendStatus(ctx, await store.getAuthorizationStatus());
}

export async function cancelOpenAICodexDevice(ctx: ApiCtx): Promise<void> {
  const authorized = await actor(ctx);
  if (!authorized) return;
  const store = storeOrUnavailable(ctx);
  if (!store) return;
  const status = await store.cancelAuthorization(authorized.id);
  audit(ctx.deps, {
    principalId: authorized.id,
    action: "openai-codex.cancel",
    resource: "openai-codex",
    scopeLabel: orgScope(ctx.deps),
  });
  return sendStatus(ctx, status);
}

export async function deleteOpenAICodexProvider(ctx: ApiCtx): Promise<void> {
  const authorized = await actor(ctx);
  if (!authorized) return;
  const store = storeOrUnavailable(ctx);
  if (!store) return;
  await store.disconnect(authorized.id);
  audit(ctx.deps, {
    principalId: authorized.id,
    action: "openai-codex.disconnect",
    resource: "openai-codex",
    scopeLabel: orgScope(ctx.deps),
  });
  return sendJson(ctx.res, 200, { ok: true });
}
