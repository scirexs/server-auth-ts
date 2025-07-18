export {
  HandledError,
  validateHeader,
  validateOrigin,
  getStandardHeaders,
  getSetCookieHeader,
  clearSetCookieHeader,
  extractBody,
  parseCookies,
  getFingerprint,
  getIPAddress,
  getVerifyData,
  sendMail,
  createSignupMail,
  genVerifyCode,
  genUUID,
  getDOSignup,
  getDOLogin,
  getDOSession,
  getDORateLimit,
}

import { webcrypto } from "crypto";
import { Resend, type CreateEmailOptions } from "resend";
import { ORIGINS, COOKIE_DOMAIN, CORS_HEADERS, SECURITY_HEADERS } from "./constants.js";
import type { DOSignupVerify, DOUserSession, DORateLimit, DOLoginRequest } from "./cfobj.js";
import type { ResponseHeaders } from "./types.js";

class HandledError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function validateHeader(headers: Headers, header: string, fn: (v: string) => boolean, code: number, msg: string) {
  const value = headers.get(header);
  if (value?.trim() && fn(value)) return;
  throw new HandledError(code, msg);
}
function validateOrigin(headers: Headers) {
  const secFetchSite = headers.get("Sec-Fetch-Site");
  if (secFetchSite && secFetchSite === "same-origin") return;
  const origin = headers.get("Origin");
  if (ORIGINS.includes(origin?.trim() ?? "")) return;
  throw new HandledError(403, "Wrong security headers for CSRF");
}

function getStandardHeaders(headers?: ResponseHeaders): ResponseHeaders {
  return {
    ...CORS_HEADERS,
    ...SECURITY_HEADERS,
    "Content-Type": "application/json",
    ...headers,
  };
}
function getSetCookieHeader(sessionId: string): ResponseHeaders {
  return { "Set-Cookie": `session=${sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/; Domain=${COOKIE_DOMAIN}` };
}
function clearSetCookieHeader(): ResponseHeaders {
  return { "Set-Cookie": `session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0; Domain=${COOKIE_DOMAIN}` };
}

async function extractBody(request: Request, ...props: string[]): Promise<Record<string, string>> {
  try {
    const data = await request.json() as Record<string, string>;
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error();
    for (const prop of props) {
      if (!Object.hasOwn(data, prop) || typeof data[prop] !== "string") throw new Error();
    }
    return data as Record<string, string>;
  } catch (e) {
    throw new HandledError(400, "Request has invalid data");
  }
}
function parseCookies(headers: Headers): Record<string, string> {
  const cookieHeader = headers.get("Cookie");
  if (!cookieHeader) return {};

  return cookieHeader
    .split("; ")
    .reduce((cookies, cookie) => {
      const [name, value] = cookie.split("=");
      cookies[name] = value;
      return cookies;
    }, {} as Record<string, string>);
}
async function getFingerprint(headers: Headers): Promise<string> {
  const ip = getIPSubnet(getIPAddress(headers));
  const ua = getNormalizeUserAgent(headers);
  const lang = headers.get("Accept-Language") ?? "";
  const mobile = headers.get("Sec-Ch-Ua-Mobile") ?? "";
  const platform = headers.get("Sec-Ch-Ua-Platform") ?? "";
  const country = headers.get("CF-IPCountry") ?? "";
  return await computeHash(`${ip}${ua}${lang}${mobile}${platform}${country}`);
}
function getNormalizeUserAgent(headers: Headers): string {
  const ua = headers.get("User-Agent")?.trim();
  if (!ua) return "";
  return ua.split(" ").map((x) => x ? x.split("/")[0] : "").join(" "); // remove versions
}
function getIPAddress(headers: Headers): string {
  return headers.get("CF-Connecting-IP")
    || headers.get("X-Forwarded-For")?.split(",")[0]?.trim()
    || headers.get("Forwarded")?.split(",")[0]?.trim()
    || "";
}
function getIPSubnet(ip: string): string {
  if (!ip) return "";
  const seg = ip.split(".");
  if (seg.length !== 4) return ip;
  return `${seg[0]}.${seg[1]}.${seg[2]}.0`;
}
async function computeHash(str: string): Promise<string> {
  const buf = new TextEncoder().encode(str);
  const hash = new Uint8Array(await webcrypto.subtle.digest("SHA-256", buf));
  return Array.from(hash)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}
function getVerifyData(key: string, token: string, ip: string): FormData {
  const formData = new FormData();
  formData.append("secret", key);
  formData.append("response", token);
  formData.append("remoteip", ip);
  return formData;
}

async function sendMail(apikey: string, payload: CreateEmailOptions) {
  const resend = new Resend(apikey);
  await resend.emails.send(payload);
}
function createSignupMail(to: string, code: string): CreateEmailOptions {
  return {
    from: "NoReply <no_reply@scirexs.dev>",
    to,
    subject: "[Account Registration] Email Address Verification",
    text: `To activate your account, you need to verify your email address. Please enter the following code on the verification page.\n\n${code}\n\nIf you do not recognize this email, please ignore it.`,
  };
}

function genVerifyCode(len: number): string {
  const SOURCE = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstvwxyz23456789";
  const LEN = 55;
  let result = "";
  for (let i = 0; i < len; i++) {
    const index = Math.trunc(Math.random() * LEN);
    result += SOURCE.slice(index, index + 1);
  }
  return result;
}
function genUUID(): string {
  return webcrypto.randomUUID();
}
function getDOSignup(env: Env): DurableObjectStub<DOSignupVerify> {
  return env.SIGNUP_VERIFY.get(env.SIGNUP_VERIFY.idFromName("signup"));
}
function getDOLogin(env: Env): DurableObjectStub<DOLoginRequest> {
  return env.LOGIN_REQUEST.get(env.LOGIN_REQUEST.idFromName("login"));
}
function getDOSession(env: Env): DurableObjectStub<DOUserSession> {
  return env.USER_SESSION.get(env.USER_SESSION.idFromName("session"));
}
function getDORateLimit(env: Env): DurableObjectStub<DORateLimit> {
  return env.RATE_LIMIT.get(env.RATE_LIMIT.idFromName("rate_limit"));
}
