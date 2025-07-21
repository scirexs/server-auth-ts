export { DOSignupVerify, DOUserSession, DORateLimit, DOLoginRequest };

import { ENDPOINT } from "./constants.js";
import {
  isRateLimited,
  validateHeaders,
  verifyTurnstile,
  createPreflightResponse,
  createJSONResponse,
  responseDummySignup,
  sendVerifyCode,
  resendVerifyCode,
  verifyCode,
  checkMailAddressFormat,
  responseDummyHello,
  prepareLogin,
  loadPrepare,
  authUser,
  getSessionHeader,
  getEmptySessionHeader,
  verifySession,
} from "./processes.js";
import {
  HandledError,
  extractBody,
  getDOSignup,
  getDOLogin,
  getDOSession,
  getDORateLimit,
} from "./utils.js";
import { D1Runner, DOSignupVerify, DOUserSession, DORateLimit, DOLoginRequest } from "./cfobj.js";

async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const method = request.method;
  const pathname = url.pathname;

  if (method === "OPTIONS") return createPreflightResponse();
  if (method !== "POST") throw new HandledError(405, `${method} method is not allowed`);
  if (await isRateLimited(request.headers, env)) throw new HandledError(429, "Too many requests. Please try again later.");

  switch (pathname) {
    case ENDPOINT.CLEANUP: return await handleCleanup(request, env);
    case ENDPOINT.SIGNUP: return await handleSignup(request, env);
    case ENDPOINT.RESEND: return await handleResend(request, env);
    case ENDPOINT.VERIFY: return await handleVerify(request, env);
    case ENDPOINT.HELLO: return await handleLoginHello(request, env);
    case ENDPOINT.LOGIN: return await handleLoginAuth(request, env);
    case ENDPOINT.LOGOUT: return await handleLogout(request, env);
    case ENDPOINT.WHOAMI: return await handleWhoami(request, env);
    default: throw new HandledError(404, "Endpoint not found");
  }
};

async function handleCleanup(_request: Request, env: Env): Promise<Response> {
  await Promise.all([
    getDORateLimit(env).cleanup(),
    getDOSignup(env).cleanup(),
    getDOLogin(env).cleanup(),
    getDOSession(env).cleanup(),
  ]);

  return createJSONResponse({ success: true });
}

async function handleSignup(request: Request, env: Env): Promise<Response> {
  validateHeaders(request.headers);
  const { username, salt, verifier, turnstile } = await extractBody(request, "username", "salt", "verifier", "turnstile");
  await verifyTurnstile(request.headers, turnstile, env.TURNSTILE_SECRET_KEY);

  checkMailAddressFormat(username);
  const d1 = new D1Runner(env);
  if (await d1.existsActiveUsername(username)) return await responseDummySignup(); // dummy response
  const userid = await d1.upsertPendingUser(username, salt, verifier);
  await sendVerifyCode(getDOSignup(env), userid, username, env.RESEND_API_KEY);

  return createJSONResponse({ success: true, userid }, 201);
}

async function handleResend(request: Request, env: Env): Promise<Response> {
  validateHeaders(request.headers);
  const { userid, username, turnstile } = await extractBody(request, "userid", "username", "turnstile");
  await verifyTurnstile(request.headers, turnstile, env.TURNSTILE_SECRET_KEY);

  if (username !== await new D1Runner(env).getUsername(userid)) throw new HandledError(403, "Wrong username");
  await resendVerifyCode(getDOSignup(env), userid, env.RESEND_API_KEY);

  return createJSONResponse({ success: true });
}

async function handleVerify(request: Request, env: Env): Promise<Response> {
  validateHeaders(request.headers);
  const { userid, code, turnstile } = await extractBody(request, "userid", "code", "turnstile");
  await verifyTurnstile(request.headers, turnstile, env.TURNSTILE_SECRET_KEY);

  await verifyCode(getDOSignup(env), userid, code);
  await new D1Runner(env).activateUser(userid);
  const header = await getSessionHeader(getDOSession(env), request.headers, userid);

  return createJSONResponse({ success: true }, 201, header);
}

async function handleLoginHello(request: Request, env: Env): Promise<Response> {
  validateHeaders(request.headers);
  const { username, client, turnstile } = await extractBody(request, "username", "client", "turnstile");
  await verifyTurnstile(request.headers, turnstile, env.TURNSTILE_SECRET_KEY);

  const d1 = new D1Runner(env);
  const row = await d1.readDataForLogin(username);
  if (!row) return responseDummyHello(); // dummy response
  const body = await prepareLogin(getDOLogin(env), row, username, client);

  return createJSONResponse(body);
}

async function handleLoginAuth(request: Request, env: Env): Promise<Response> {
  validateHeaders(request.headers);
  const { requestId, evidence, turnstile } = await extractBody(request, "requestId", "evidence", "turnstile");
  await verifyTurnstile(request.headers, turnstile, env.TURNSTILE_SECRET_KEY);

  const data = await loadPrepare(getDOLogin(env), requestId);
  const body = await authUser(data, requestId, evidence);
  if (!body.success) return createJSONResponse(body, 401);
  await new D1Runner(env).updateLastLogin(data.userid);
  const header = await getSessionHeader(getDOSession(env), request.headers, data.userid);

  return createJSONResponse(body, 201, header);
}

async function handleLogout(request: Request, env: Env): Promise<Response> {
  validateHeaders(request.headers);

  const header = await getEmptySessionHeader(getDOSession(env), request.headers);

  return createJSONResponse({ success: true }, 200, header);
}

async function handleWhoami(request: Request, env: Env): Promise<Response> {
  validateHeaders(request.headers);

  const [userid, header] = await verifySession(getDOSession(env), request.headers);
  if (!userid) throw new HandledError(401, "Active session not found");
  const username = await new D1Runner(env).getUsername(userid);
  if (!username) throw new HandledError(410, "User ID is not active");

  return createJSONResponse({ username }, undefined, header);
}

async function handleError(e: any): Promise<Response> {
  const handled = e instanceof HandledError;
  if (!handled) console.error("Unhandled error or send mail error:", e);

  const response = handled
    ? new HandledError(400, "Bad request")
    : new HandledError(500, "Internal server error occurred");
  return createJSONResponse({ success: false, message: response.message }, response.status);
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    try {
      return await handleRequest(request, env);
    } catch (e) {
      return await handleError(e);
    }
  }
} satisfies ExportedHandler<Env>;
