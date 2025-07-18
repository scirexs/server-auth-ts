import { DurableObject } from "cloudflare:workers";
import { PREFIX, SQL, TTL, INTERVAL } from "./constants.js";
import { genUUID, genVerifyCode } from "./utils.js";
import type { SignupVerify, LoginRequest, LoginSession, RateLimit, SandboxUsers, RowCount, KeyPair } from "./types.js";

export class D1Runner {
  #d1: D1Database;
  constructor(env: Env) {
    this.#d1 = env.D1;
  }
  async existsActiveUsername(username: string): Promise<boolean> {
    const row = await this.#d1.prepare(SQL.EXISTS_NAME).bind(username).first<RowCount>();
    return Boolean(row?.count);
  }
  async upsertPendingUser(username: string, salt: string, verifier: string): Promise<string> {
    const userid = genUUID();
    await this.#d1.batch([
      this.#d1.prepare(SQL.REMOVE).bind(username),
      this.#d1.prepare(SQL.SIGNUP).bind(userid, username, salt, verifier),
    ]);
    return userid;
  }
  async activateUser(userid: string) {
    await this.#d1.prepare(SQL.ACTIVATE).bind(userid).run();
  }
  async readDataForLogin(username: string): Promise<SandboxUsers | null> {
    return await this.#d1.prepare(SQL.HELLO).bind(username).first<SandboxUsers>();
  }
  async updateLastLogin(userid: string) {
    await this.#d1.prepare(SQL.LOGIN).bind(userid).run();
  }
  async getUsername(userid: string): Promise<string> {
    const row = await this.#d1.prepare(SQL.USERNAME).bind(userid).first<SandboxUsers>();
    return row ? row.username : "";
  }
}

export class DOSignupVerify extends DurableObject<Env> {
  #storage: DurableObjectStorage;
  static get expire(): number {
    return Date.now() + TTL.VERIFY; // 10min
  }
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.#storage = ctx.storage;
  }

  async store(userid: string, username: string): Promise<string> {
    const id = `${PREFIX}${userid}`;
    const code = genVerifyCode(6);
    await this.#storage.put(id, { code, username, count: 0, expire: DOSignupVerify.expire });
    return code;
  }
  async read(userid: string): Promise<SignupVerify | undefined> {
    const id = `${PREFIX}${userid}`;
    const obj = await this.#storage.get<SignupVerify>(id);
    if (!obj) return;
    return obj;
  }
  async countup(userid: string, obj: SignupVerify) {
    const id = `${PREFIX}${userid}`;
    obj.count++;
    await this.#storage.put(id, obj);
  }
  async delete(userid: string) {
    const id = `${PREFIX}${userid}`;
    await this.#storage.delete(id);
  }
  async cleanup() {
    if (await this.#storage.getAlarm()) return;
    await this.alarm();
  }
  async alarm() {
    try {
      await this.#cleanup();
      await this.#setNextAlarm(INTERVAL.CLEANUP);
    } catch (e) {
      console.error("SignupVerify alarm execution failed:", e);
      await this.#setNextAlarm(INTERVAL.RETRY);
    }
  }
  async #cleanup() {
    const map = await this.#storage.list({ prefix: PREFIX });
    const now = Date.now();
    const targets: string[] = [];
    for (const [k, v] of map.entries() as MapIterator<[string, SignupVerify]>) {
      if (v.expire < now) targets.push(k);
    }
    await this.#storage.delete(targets);
    console.log(`Cleanup SignupVerify: ${targets.length} / ${map.size}`);
  }
  async #setNextAlarm(interval: number) {
    const next = Date.now() + interval;
    await this.#storage.setAlarm(next);
  }
}

export class DOUserSession extends DurableObject<Env> {
  #storage: DurableObjectStorage;
  static get expire(): number {
    return Date.now() + TTL.SESSION; // 1week
  }
  static get refresh(): number {
    return Date.now() + TTL.REFRESH; // 30min
  }
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.#storage = ctx.storage;
  }

  async start(userid: string, fp: string): Promise<string> {
    const sessionId = genUUID();
    const id = `${PREFIX}${sessionId}`;
    const obj = DOUserSession.#newSession(userid, fp);
    await this.#storage.put(id, obj);
    return sessionId;
  }
  async verify(sessionId: string, fp: string): Promise<LoginSession | undefined> {
    const id = `${PREFIX}${sessionId}`;
    const obj = await this.#storage.get<LoginSession>(id);
    if (!obj) return undefined;
    if (await this.#isExpired(id, obj)) return undefined;
    if (await this.#isInvalidFP(id, obj, fp)) return undefined;
    if (await this.#refresh(id, obj)) return obj;
    obj.expire = DOUserSession.expire;
    this.#storage.put(id, obj);
    return obj;
  }
  async #isExpired(id: string, obj: LoginSession): Promise<boolean> {
    if (Date.now() <= obj.expire) return false;
    await this.#storage.delete(id);
    return true;
  }
  async #isInvalidFP(id: string, obj: LoginSession, fp: string): Promise<boolean> {
    if (obj.fingerprint === fp) return false;
    await this.#storage.delete(id);
    return true;
  }
  async #refresh(id: string, obj: LoginSession): Promise<boolean> {
    if (Date.now() <= obj.refresh) return false;
    obj.keep = false;
    await this.#storage.delete(id);
    return true;
  }
  async delete(sessionId: string) {
    const id = `${PREFIX}${sessionId}`;
    await this.#storage.delete(id);
  }
  async cleanup() {
    if (await this.#storage.getAlarm()) return;
    await this.alarm();
  }
  async alarm() {
    try {
      await this.#cleanup();
      await this.#setNextAlarm(INTERVAL.CLEANUP);
    } catch (e) {
      console.error("UserSession alarm execution failed:", e);
      await this.#setNextAlarm(INTERVAL.RETRY);
    }
  }
  async #cleanup() {
    const map = await this.#storage.list({ prefix: PREFIX });
    const now = Date.now();
    const targets: string[] = [];
    for (const [k, v] of map.entries() as MapIterator<[string, LoginSession]>) {
      if (v.expire < now) targets.push(k);
    }
    await this.#storage.delete(targets);
    console.log(`Cleanup UserSession: ${targets.length} / ${map.size}`);
  }
  async #setNextAlarm(interval: number) {
    const next = Date.now() + interval;
    await this.#storage.setAlarm(next);
  }
  static #newSession(userid: string, fingerprint: string): LoginSession {
    return { userid, refresh: DOUserSession.refresh, expire: DOUserSession.expire, keep: true, fingerprint };
  }
}

export class DORateLimit extends DurableObject<Env> {
  #storage: DurableObjectStorage;
  static get expire(): number {
    return Date.now() + TTL.RATE_LIMIT; // 10min
  }
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.#storage = ctx.storage;
  }

  async count(ip: string): Promise<number> {
    const id = `${PREFIX}${ip}`;
    const obj = await this.#storage.get<RateLimit>(id);
    if (!obj) return await this.#init(id);
    if (Date.now() > obj.expire) return await this.#init(id);
    obj.count++;
    await this.#storage.put(id, obj);
    return obj.count;
  }
  async #init(id: string): Promise<number> {
    await this.#storage.put(id, { count: 1, expire: DORateLimit.expire });
    return 1;
  }
  async cleanup() {
    if (await this.#storage.getAlarm()) return;
    await this.alarm();
  }
  async alarm() {
    try {
      await this.#cleanup();
      await this.#setNextAlarm(INTERVAL.CLEANUP);
    } catch (e) {
      console.error("RateLimit alarm execution failed:", e);
      await this.#setNextAlarm(INTERVAL.RETRY);
    }
  }
  async #cleanup() {
    const map = await this.#storage.list({ prefix: PREFIX });
    const now = Date.now();
    const targets: string[] = [];
    for (const [k, v] of map.entries() as MapIterator<[string, RateLimit]>) {
      if (v.expire < now) targets.push(k);
    }
    await this.#storage.delete(targets);
    console.log(`Cleanup RateLimit: ${targets.length} / ${map.size}`);
  }
  async #setNextAlarm(interval: number) {
    const next = Date.now() + interval;
    await this.#storage.setAlarm(next);
  }
}

export class DOLoginRequest extends DurableObject<Env> {
  #storage: DurableObjectStorage;
  static get expire(): number {
    return Date.now() + TTL.HELLO; // 1min
  }
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.#storage = ctx.storage;
  }

  async store(userid: string, username: string, salt: string, verifier: string, client: string, pair: KeyPair): Promise<string> {
    const obj = { userid, username, salt, verifier, client, pair, expire: DOLoginRequest.expire };
    const requestId = genUUID();
    const id = `${PREFIX}${requestId}`;
    await this.#storage.put(id, obj);
    return requestId;
  }
  async read(requestId: string): Promise<LoginRequest | undefined> {
    const id = `${PREFIX}${requestId}`;
    const obj = await this.#storage.get<LoginRequest>(id);
    if (!obj) return;
    await this.#storage.delete(id);
    return obj;
  }
  async cleanup() {
    if (await this.#storage.getAlarm()) return;
    await this.alarm();
  }
  async alarm() {
    try {
      await this.#cleanup();
      await this.#setNextAlarm(INTERVAL.CLEANUP);
    } catch (e) {
      console.error("LoginRequest alarm execution failed:", e);
      await this.#setNextAlarm(INTERVAL.RETRY);
    }
  }
  async #cleanup() {
    const map = await this.#storage.list({ prefix: PREFIX });
    const now = Date.now();
    const targets: string[] = [];
    for (const [k, v] of map.entries() as MapIterator<[string, LoginRequest]>) {
      if (v.expire < now) targets.push(k);
    }
    await this.#storage.delete(targets);
    console.log(`Cleanup LoginRequest: ${targets.length} / ${map.size}`);
  }
  async #setNextAlarm(interval: number) {
    const next = Date.now() + interval;
    await this.#storage.setAlarm(next);
  }
}
