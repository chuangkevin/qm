import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";
import { errMessage } from "../util/errors.ts";
import { isPrivateNetworkIp } from "../util/network.ts";
import { isProbablyBinary } from "./seed.ts";
import { isExcludedPath, matchesAny } from "./ingest.ts";
import type { FetchedRepo, RepoFile } from "./ingest.ts";
import type { PackConfig } from "./normalize.ts";
import type { SkillPack } from "./skill-pack-store.ts";

export interface SkillPackFetcher {
  fetch(pack: SkillPack): Promise<FetchedRepo>;
  resolveRef(pack: SkillPack): Promise<string>;
}

export interface GitFetcherOptions {
  resolveAuth?: (pack: SkillPack) => Promise<GitAuth | undefined>;
  gitBin?: string;
  timeoutMs?: number;
  maxFiles?: number;
  maxTotalBytes?: number;
  allowLocalRepos?: boolean;
  lookup?: (host: string) => Promise<string[]>;
}

export interface PackTokenSources {
  serviceCredential(slug: string): Promise<
    | {
        secret: string;
        host: string;
        enabled: boolean;
        injection?: { header?: string; scheme?: string };
        allowedMethods?: string[];
        allowedPathPrefixes?: string[];
      }
    | undefined
  >;
  connectorToken(host: string, principalId: string): Promise<string | undefined>;
}

export interface GitAuth {
  header: string;
  value: string;
  secret: string;
}

function normalizedHost(repoUrl: string): string | null {
  try {
    return new URL(repoUrl).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

function connectorHostFor(repoUrl: string): string | null {
  const host = normalizedHost(repoUrl);
  if (!host) return null;
  if (host === "github.com" || host === "api.github.com") return "api.github.com";
  return null;
}

interface ValidatedRepo {
  url: string;
  gitConfig: Array<[string, string]>;
}

async function validateRepoUrl(
  raw: string,
  allowLocalRepos: boolean,
  lookup: (host: string) => Promise<string[]>,
): Promise<ValidatedRepo> {
  if (typeof raw !== "string" || !raw.trim()) throw new Error("skill pack url is required");
  if (allowLocalRepos && raw.startsWith("/")) return { url: raw, gitConfig: [] };
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("skill pack url must use https");
  }
  if (url.protocol !== "https:" || !url.hostname || url.username || url.password) {
    throw new Error("skill pack url must use credential-free https");
  }
  const host = url.hostname.toLowerCase().replace(/^\[(.*)\]$/, "$1");
  const literal = isIP(host) !== 0;
  let addresses: string[];
  try {
    addresses = literal ? [host] : await lookup(host);
  } catch {
    throw new Error("skill pack repository hostname could not be resolved");
  }
  if (!addresses.length || addresses.some((address) => isPrivateNetworkIp(address))) {
    throw new Error("skill pack repository must resolve to a public network address");
  }
  const port = url.port || "443";
  const resolved = addresses.map((address) => (isIP(address) === 6 ? `[${address}]` : address)).join(",");
  return {
    url: url.toString(),
    gitConfig: [
      ["http.followRedirects", "false"],
      ...(!literal ? [["http.curloptResolve", `${host}:${port}:${resolved}`] as [string, string]] : []),
      ["http.proxy", ""],
    ],
  };
}

export async function resolvePackAuth(
  sources: PackTokenSources,
  pack: Pick<SkillPack, "url" | "authCredentialSlug" | "createdBy">,
): Promise<GitAuth | undefined> {
  if (pack.authCredentialSlug) {
    const credential = await sources.serviceCredential(pack.authCredentialSlug);
    if (!credential?.enabled) return undefined;
    const repo = new URL(pack.url);
    const repoHost = normalizedHost(pack.url);
    const credentialHost = normalizedHost(`https://${credential.host}`) ?? credential.host.toLowerCase();
    if (!repoHost || (repoHost !== credentialHost && connectorHostFor(pack.url) !== credentialHost)) {
      throw new Error(`skill pack credential is not authorized for ${repoHost ?? "this repository"}`);
    }
    const methods = credential.allowedMethods?.map((method) => method.toUpperCase());
    if (methods && (!methods.includes("GET") || !methods.includes("POST"))) {
      throw new Error("skill pack credential must allow Git HTTP GET and POST");
    }
    if (
      credential.allowedPathPrefixes?.length &&
      !credential.allowedPathPrefixes.some((prefix) => repo.pathname.startsWith(prefix))
    ) {
      throw new Error(`skill pack credential is not authorized for ${repo.pathname}`);
    }
    const header = credential.injection?.header?.trim() || "Authorization";
    const scheme = credential.injection?.scheme ?? "Bearer ";
    return { header, value: `${scheme}${credential.secret}`, secret: credential.secret };
  }
  const host = connectorHostFor(pack.url);
  if (host) {
    const token = await sources.connectorToken(host, pack.createdBy);
    if (token) return { header: "Authorization", value: `Bearer ${token}`, secret: token };
  }
  return undefined;
}

const SHA_RE = /^[0-9a-f]{7,40}$/;
const BRANCH_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/;

const execFileP = promisify(execFile);

function scrub(s: string, auth: GitAuth | undefined): string {
  return auth ? s.split(auth.secret).join("***").split(auth.value).join("***") : s;
}

export function createGitFetcher(opts: GitFetcherOptions = {}): SkillPackFetcher {
  const gitBin = opts.gitBin ?? "git";
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const maxFiles = opts.maxFiles ?? 5000;
  const maxTotalBytes = opts.maxTotalBytes ?? 32 * 1024 * 1024;
  const allowLocalRepos = opts.allowLocalRepos === true;
  const lookup =
    opts.lookup ??
    ((host: string) =>
      dnsLookup(host, { all: true, verbatim: true }).then((results) => results.map((result) => result.address)));

  function gitEnv(cwd: string, auth: GitAuth | undefined, config: Array<[string, string]>): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = { ...globalThis.process.env };
    for (const k of Object.keys(env)) if (/^(GIT_|SSH_)/.test(k)) delete env[k];
    env.HOME = cwd;
    env.GIT_TERMINAL_PROMPT = "0";
    env.GIT_CONFIG_NOSYSTEM = "1";
    env.GIT_CONFIG_GLOBAL = "/dev/null";
    env.GIT_ALLOW_PROTOCOL = allowLocalRepos ? "https:file" : "https";
    const entries = [
      ...config,
      ...(auth ? [["http.extraHeader", `${auth.header}: ${auth.value}`] as [string, string]] : []),
    ];
    if (entries.length) {
      env.GIT_CONFIG_COUNT = String(entries.length);
      entries.forEach(([key, value], index) => {
        env[`GIT_CONFIG_KEY_${index}`] = key;
        env[`GIT_CONFIG_VALUE_${index}`] = value;
      });
    }
    return env;
  }

  async function git(
    args: string[],
    cwd: string,
    auth: GitAuth | undefined,
    config: Array<[string, string]> = [],
  ): Promise<string> {
    try {
      return (
        await execFileP(gitBin, args, {
          cwd,
          env: gitEnv(cwd, auth, config),
          timeout: timeoutMs,
          killSignal: "SIGKILL",
          maxBuffer: 64 * 1024 * 1024,
        })
      ).stdout;
    } catch (e) {
      if ((e as { killed?: boolean }).killed)
        throw new Error(`git ${args[0]} timed out after ${timeoutMs}ms`, { cause: e });
      throw new Error(scrub(errMessage(e), auth), { cause: e });
    }
  }

  /**
   * 把 skillGlobs 轉成 sparse-checkout cone 模式吃得下的目錄清單。
   * cone 模式只認目錄前綴，所以取每個 glob 第一個含萬用字元的節之前那段。
   *   "plugins/sara-backend/skills/*"  -> "plugins/sara-backend/skills"
   *   "skills/**"                      -> "skills"
   * 整個 pattern 就是萬用字元（"*"、"**"）代表要整個 repo，回空陣列＝不做 sparse。
   */
  function sparseDirs(globs: string[] | undefined): string[] {
    if (!globs || globs.length === 0) return [];
    const dirs = new Set<string>();
    for (const g of globs) {
      const parts = String(g).split("/");
      const keep: string[] = [];
      for (const part of parts) {
        if (part.includes("*") || part.includes("?") || part.includes("[")) break;
        if (part === "" || part === ".") continue;
        if (part === "..") return [];   // 路徑往上跳，不安全，放棄 sparse
        keep.push(part);
      }
      if (keep.length === 0) return [];  // 有一個 glob 涵蓋整個 repo，sparse 沒意義
      dirs.add(keep.join("/"));
    }
    return [...dirs];
  }

  /**
   * 走訪 checkout 並讀進檔案內容。
   *
   * 篩選一定要發生在 readFile 之前——被 exclude 掉的檔案不該讀，也不該計入
   * maxTotalBytes。原本是整個 repo 讀完才交給 ingest 篩，所以 sara-agents-configuration
   * 裡跟 skill 無關的檔案照樣把 32MB 上限撐爆，背景 skill-sync 每 5 分鐘失敗一次
   * （2026-09-10：`pack exceeds max bytes (33554432)`）。
   */
  async function readTree(root: string, config?: PackConfig): Promise<RepoFile[]> {
    const files: RepoFile[] = [];
    let totalBytes = 0;
    const wanted = (rel: string): boolean => {
      if (isExcludedPath(rel, config?.exclude)) return false;
      if (!config?.skillGlobs?.length) return true;
      // skillGlobs 指的是 skill 目錄；目錄本身或它底下的檔案都要留
      if (matchesAny(rel, config.skillGlobs)) return true;
      const parts = rel.split("/");
      for (let i = 1; i < parts.length; i++) {
        if (matchesAny(parts.slice(0, i).join("/"), config.skillGlobs)) return true;
      }
      return false;
    };
    const walk = async (absDir: string): Promise<void> => {
      for (const ent of await readdir(absDir, { withFileTypes: true })) {
        if (ent.name === ".git") continue;
        if (ent.isSymbolicLink()) continue;
        const abs = join(absDir, ent.name);
        const rel = relative(root, abs).split(sep).join("/");
        if (ent.isDirectory()) {
          if (isExcludedPath(rel, config?.exclude)) continue;
          await walk(abs);
          continue;
        }
        if (!ent.isFile()) continue;
        if (!wanted(rel)) continue;
        if (files.length >= maxFiles) throw new Error(`pack exceeds max files (${maxFiles})`);
        const buf = await readFile(abs);
        totalBytes += buf.length;
        if (totalBytes > maxTotalBytes) throw new Error(`pack exceeds max bytes (${maxTotalBytes})`);
        const binary = isProbablyBinary(buf);
        files.push({
          path: relative(root, abs).split(sep).join("/"),
          text: binary ? "" : buf.toString("utf8"),
          binary,
        });
      }
    };
    await walk(root);
    return files.sort((a, b) => {
      if (a.path < b.path) return -1;
      if (a.path > b.path) return 1;
      return 0;
    });
  }

  return {
    async fetch(pack) {
      const ref = (pack.ref ?? "").trim();
      if (ref && !SHA_RE.test(ref) && !BRANCH_RE.test(ref)) throw new Error(`invalid skill pack ref: ${ref}`);
      const repo = await validateRepoUrl(pack.url, allowLocalRepos, lookup);
      const auth = opts.resolveAuth ? await opts.resolveAuth(pack) : undefined;

      const work = await mkdtemp(join(tmpdir(), "qm-skill-src-"));
      const repoDir = join(work, "repo");
      try {
        // --filter=blob:none：只先抓 commit 與 tree，檔案內容等 checkout 需要時才拉。
        // 配合下面的 sparse-checkout，等於只下載 skillGlobs 涵蓋的那些檔案。
        // 沒有這一段時 clone 會把整個 repo 的歷史檔案內容抓下來——包含永遠不會匯入的
        // 大檔——sara-agents-configuration 因此在 60 秒 timeout 內 clone 不完。
        // 伺服器不支援 partial clone 時退回一般 clone，行為與加這段之前相同。
        const cone = sparseDirs(pack.config?.skillGlobs);
        const cloneArgs = ["clone", "--no-checkout", "--quiet"];
        let partial = cone.length > 0;
        if (partial) cloneArgs.push("--filter=blob:none");
        try {
          await git([...cloneArgs, repo.url, "repo"], work, auth, repo.gitConfig);
        } catch (e) {
          if (!partial) throw e;
          partial = false;
          await rm(repoDir, { recursive: true, force: true }).catch(() => {});
          await git(["clone", "--no-checkout", "--quiet", repo.url, "repo"], work, auth, repo.gitConfig);
        }

        // 只 checkout skillGlobs 涵蓋的目錄。沒有這一段時 checkout 會展開整個 repo，
        // 其中與 skill 無關的大檔（範例圖片、音檔）照樣計入 readTree 的 maxTotalBytes，
        // 讓 pack 因為它根本不會匯入的檔案而爆掉（實例：sara-agents-configuration
        // 79 MB，其中 ppt-master 的參考素材佔 75 MB，skill 本身只有 3.7 MB）。
        if (cone.length > 0) {
          try {
            await git(["sparse-checkout", "init", "--cone"], repoDir, undefined);
            await git(["sparse-checkout", "set", ...cone], repoDir, undefined);
          } catch {
            // git 太舊或不支援 cone 模式時退回整棵樹，行為與加這段之前相同
            await git(["sparse-checkout", "disable"], repoDir, undefined).catch(() => {});
          }
        }
        // partial clone 的檔案內容是 checkout 當下才向遠端拉的（promisor fetch），
        // 所以這一步仍需要憑證；一般 clone 不連網，維持原本不帶憑證的呼叫。
        try {
          await git(
            ["checkout", "--detach", "--quiet", ref || "HEAD"],
            repoDir,
            partial ? auth : undefined,
            partial ? repo.gitConfig : [],
          );
        } catch (e) {
          if (!partial) throw e;
          // 遠端不支援 promisor fetch 時，改用一般 clone 重來一次
          await rm(repoDir, { recursive: true, force: true }).catch(() => {});
          await git(["clone", "--no-checkout", "--quiet", repo.url, "repo"], work, auth, repo.gitConfig);
          if (cone.length > 0) {
            try {
              await git(["sparse-checkout", "init", "--cone"], repoDir, undefined);
              await git(["sparse-checkout", "set", ...cone], repoDir, undefined);
            } catch {
              await git(["sparse-checkout", "disable"], repoDir, undefined).catch(() => {});
            }
          }
          await git(["checkout", "--detach", "--quiet", ref || "HEAD"], repoDir, undefined);
        }
        const commit = (await git(["rev-parse", "HEAD"], repoDir, undefined)).trim();
        const files = await readTree(repoDir, pack.config);
        return { commit, files };
      } finally {
        await rm(work, { recursive: true, force: true }).catch(() => {});
      }
    },

    async resolveRef(pack) {
      const ref = (pack.ref ?? "").trim();
      if (ref && !SHA_RE.test(ref) && !BRANCH_RE.test(ref)) throw new Error(`invalid skill pack ref: ${ref}`);
      const repo = await validateRepoUrl(pack.url, allowLocalRepos, lookup);
      const auth = opts.resolveAuth ? await opts.resolveAuth(pack) : undefined;
      const target = ref && BRANCH_RE.test(ref) && !SHA_RE.test(ref) ? ref : "HEAD";
      const work = await mkdtemp(join(tmpdir(), "qm-skill-ref-"));
      try {
        const out = await git(["ls-remote", repo.url, target], work, auth, repo.gitConfig);
        const sha =
          out
            .split("\n")
            .map((l) => l.trim())
            .filter(Boolean)[0]
            ?.split(/\s+/)[0] ?? "";
        if (!SHA_RE.test(sha)) throw new Error(`could not resolve ref "${target}" for skill pack`);
        return sha;
      } finally {
        await rm(work, { recursive: true, force: true }).catch(() => {});
      }
    },
  };
}
