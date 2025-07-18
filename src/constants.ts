export {
  REGEX_MAIL,
  PREFIX,
  MAX_RATE_LIMIT,
  MAX_VERIFY_LIMIT,
  INTERVAL,
  TURNSTILE_URL,
  ORIGINS,
  COOKIE_DOMAIN,
  TTL,
  CORS_HEADERS,
  SECURITY_HEADERS,
  ENDPOINT,
  SQL,
}

import type { ResponseHeaders } from "./types.js";

const REGEX_MAIL = /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
const PREFIX = "DO:";
const MAX_RATE_LIMIT = 20;
const MAX_VERIFY_LIMIT = 5;
const INTERVAL = {
  CLEANUP: 86400000, // 1day
  RETRY: 3600000, // 1hour
} as const;
const TURNSTILE_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const ORIGINS = ["https://sandbox.scirexs.dev"];
const COOKIE_DOMAIN = "scirexs.dev";
const TTL = {
  RATE_LIMIT: 600000, // 10min
  VERIFY: 600000, // 10min
  HELLO: 300000, // 5min
  SESSION: 604800000, // 1week
  REFRESH: 1800000, // 30min
} as const;
const CORS_HEADERS: ResponseHeaders = {
  "Access-Control-Allow-Origin": "https://sandbox.scirexs.dev",
  "Access-Control-Allow-Methods": "POST",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Credentials": "true", // for set-cookie
  "Access-Control-Max-Age": "86400"
};
const SECURITY_HEADERS: ResponseHeaders = {
  "X-Content-Type-Options": "nosniff", // XSS
  "X-Frame-Options": "DENY", // click jacking
  "Referrer-Policy": "strict-origin-when-cross-origin", // privacy
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'", // XSS
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload" // HSTS
};
const ENDPOINT = {
  CLEANUP: "/api/Qm0b2yf3N38yo2lD7rPC2d5Fyrn039mH0qnTbXNRYg9nefxCRq",
  SIGNUP: "/api/signup",
  RESEND: "/api/resend",
  VERIFY: "/api/verify",
  HELLO: "/api/hello",
  LOGIN: "/api/login",
  LOGOUT: "/api/logout",
  WHOAMI: "/api/whoami",
} as const;
const SQL = {
  EXISTS_NAME: "select count(userid) as count from sandbox_users where username = ? and status = 'active';",
  REMOVE: "delete from sandbox_users where username = ? and status = 'pending';",
  SIGNUP: "insert into sandbox_users (userid, username, salt, verifier) values (?, ?, ?, ?);",
  ACTIVATE: "update sandbox_users set status = 'active', last_login = datetime('now'), update_date = datetime('now') where userid = ?;",
  HELLO: "select userid, salt, verifier from sandbox_users where username = ? and status = 'active' limit 1;",
  LOGIN: "update sandbox_users set last_login = datetime('now') where userid = ?;",
  USERNAME: "select username from sandbox_users where userid = ? and status = 'active' limit 1;",
} as const;
