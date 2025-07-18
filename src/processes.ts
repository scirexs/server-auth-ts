export {
  isRateLimited,
  validateHeaders,
  verifyTurnstile,
  createJSONResponse,
  checkMailAddressFormat,
  responseDummySignup,
  sendVerifyCode,
  resendVerifyCode,
  verifyCode,
  responseDummyHello,
  prepareLogin,
  loadPrepare,
  authUser,
  getSessionHeader,
  getEmptySessionHeader,
  verifySession,
};
import { addRandomDelay, authenticate, createDummyHello, createServerHello, getDefaultConfig } from "@scirexs/srp6a/server";
import { REGEX_MAIL, MAX_RATE_LIMIT, MAX_VERIFY_LIMIT, TURNSTILE_URL } from "./constants.js";
import {
  HandledError,
  validateHeader,
  validateOrigin,
  getStandardHeaders,
  getSetCookieHeader,
  clearSetCookieHeader,
  parseCookies,
  getFingerprint,
  getIPAddress,
  getVerifyData,
  getDORateLimit,
  createSignupMail,
  sendMail,
  genUUID,
} from "./utils.js";
import { DOSignupVerify, DOUserSession, DOLoginRequest } from "./cfobj.js";
import type { ResponseHeaders, TurnstileResponse, LoginRequest, SandboxUsers } from "./types.js";

/** for all */
async function isRateLimited(headers: Headers, env: Env): Promise<boolean> {
  const ip = getIPAddress(headers);
  const [id, limit] = ip ? [ip, MAX_RATE_LIMIT] : ["unknown", MAX_RATE_LIMIT / 2];
  return await getDORateLimit(env).count(id) > limit;
}
function validateHeaders(headers: Headers) {
  validateHeader(headers, "Content-Length", (v) => Number.parseInt(v) <= 1024 * 100, 413, "Request body too large"); // 100kB
  validateHeader(headers, "Content-Type", (v) => v.includes("application/json"), 415, "Content-Type must be application/json");
  validateHeader(headers, "Accept", (v) => v.includes("application/json") || v.includes("*/*"), 406, "Server can only produce application/json");
  validateOrigin(headers); // CSRF
}
async function verifyTurnstile(headers: Headers, token: string, secret: string) {
  const ip = getIPAddress(headers);
  if (!token || !ip) throw new HandledError(403, "Required ip and turnstile token");

  const response = await fetch(TURNSTILE_URL, {
      body: getVerifyData(secret, token, ip),
      method: "POST",
  });
  const result = await response.json() as TurnstileResponse;
  if (!result.success) throw new HandledError(403, "Failed to bot check");
}
function createJSONResponse(body: any, status: number = 200, headers?: ResponseHeaders): Response {
  const json = JSON.stringify(body);
  const length = { "Content-Length": new Blob([json]).size.toString() };
  headers = { ...headers ?? {}, ...length };
  return new Response(
    JSON.stringify(body),
    {
      status,
      headers: getStandardHeaders(headers),
    }
  );
}

/** for signup */
function checkMailAddressFormat(username: string) {
  if (!REGEX_MAIL.test(username)) throw new HandledError(400, "Invalid mail address format");
}
async function responseDummySignup(): Promise<Response> {
  await addRandomDelay(10);
  return createJSONResponse({ success: true, userid: genUUID() }, 201);
}
/** for signup, resend */
async function sendVerifyCode(DO: DurableObjectStub<DOSignupVerify>, userid: string, username: string, apikey: string) {
  const code = await DO.store(userid, username);
  const payload = createSignupMail(username, code);
  await sendMail(apikey, payload);
}

/** for resend */
async function resendVerifyCode(DO: DurableObjectStub<DOSignupVerify>, userid: string, apikey: string) {
  const user = await DO.read(userid);
  if (!user?.username) throw new HandledError(403, "Wrong user id");
  await sendVerifyCode(DO, userid, user.username, apikey);
}

/** for verify */
async function verifyCode(DO: DurableObjectStub<DOSignupVerify>, userid: string, code: string) {
  const user = await DO.read(userid);
  if (!user) throw new HandledError(410, "User ID not found");
  if (user.count > MAX_VERIFY_LIMIT) {
    await DO.delete(userid);
    throw new HandledError(429, "Too many failed");
  };
  if (user.expire < Date.now()) {
    await DO.delete(userid);
    throw new HandledError(410, "Verify code is expired");
  }
  if (code !== user.code) {
    await DO.countup(userid, user);
    throw new HandledError(403, "Wrong verify code");
  }
  await DO.delete(userid);
  return true;
}

/** for hello */
async function responseDummyHello(): Promise<Response> {
  const dummy = createDummyHello(getDefaultConfig());
  await addRandomDelay(10);
  return createJSONResponse({ ...dummy, requestId: genUUID() });
}
async function prepareLogin(DO: DurableObjectStub<DOLoginRequest>, row: SandboxUsers, username: string, client: string): Promise<Record<string, string>> {
  const [hello, pair] = await createServerHello(row.salt, row.verifier, getDefaultConfig());
  const requestId = await DO.store(row.userid, username, row.salt, row.verifier, client, pair);
  return { ...hello, requestId };
}

/** for auth */
async function loadPrepare(DO: DurableObjectStub<DOLoginRequest>, requestId: string): Promise<LoginRequest> {
  const data = await DO.read(requestId);
  if (!data) throw new HandledError(404, "Request ID not found");
  if (Date.now() > data.expire) throw new HandledError(410, "Request ID is expired");
  return data;
}
async function authUser(data: LoginRequest, requestId: string, evidence: string): Promise<Record<string, string | boolean>> {
  const { username, salt, verifier, client, pair } = data;
  const result = await authenticate(username, salt, verifier, pair, client, evidence, getDefaultConfig());
  return { ...result, requestId };
}

/** for auth, verify */
async function getSessionHeader(DO: DurableObjectStub<DOUserSession>, headers: Headers | string, userid: string): Promise<ResponseHeaders> {
  const fp = typeof headers === "string" ? headers : await getFingerprint(headers);
  const session = await DO.start(userid, fp);
  return getSetCookieHeader(session);
}

/** for logout */
async function getEmptySessionHeader(DO: DurableObjectStub<DOUserSession>, headers: Headers): Promise<ResponseHeaders> {
  const { session } = parseCookies(headers);
  await DO.delete(session);
  return clearSetCookieHeader();
}

/** for whoami */
async function verifySession(DO: DurableObjectStub<DOUserSession>, headers: Headers): Promise<[string, ResponseHeaders?]> {
  const { session } = parseCookies(headers);
  if (!session) return [""];
  const fp = await getFingerprint(headers);
  const obj = await DO.verify(session, fp);
  if (!obj) return [""];
  return [obj.userid, obj.keep ? undefined : await getSessionHeader(DO, fp, obj.userid)];
}
