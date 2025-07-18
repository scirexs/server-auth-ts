import { webcrypto } from "node:crypto";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Resend } from "resend";
import {
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
} from "../src/utils.js";

// Mock Resend
vi.mock("resend", () => {
  return {
    Resend: vi.fn().mockImplementation(() => ({
      emails: {
        send: vi.fn().mockResolvedValue({ id: "test-email-id" }),
      },
    })),
  };
});

// Mock crypto.randomUUID
Object.defineProperty(globalThis, "crypto", {
  value: {
    randomUUID: vi.fn(() => "test-uuid-1234"),
    subtle: webcrypto.subtle,
  },
  writable: true,
});

// Mock environment type
interface MockEnv {
  SIGNUP_VERIFY: {
    get: (id: any) => any;
    idFromName: (name: string) => any;
  };
  LOGIN_REQUEST: {
    get: (id: any) => any;
    idFromName: (name: string) => any;
  };
  USER_SESSION: {
    get: (id: any) => any;
    idFromName: (name: string) => any;
  };
  RATE_LIMIT: {
    get: (id: any) => any;
    idFromName: (name: string) => any;
  };
}

describe("HandledError", () => {
  it("should create error with status and message", () => {
    const error = new HandledError(404, "Not found");
    expect(error.status).toBe(404);
    expect(error.message).toBe("Not found");
    expect(error instanceof Error).toBe(true);
  });
});

describe("validateHeader", () => {
  it("should pass validation when header meets criteria", () => {
    const headers = new Headers({ "content-type": "application/json" });
    expect(() => {
      validateHeader(headers, "content-type", (v) => v.includes("json"), 400, "Invalid type");
    }).not.toThrow();
  });

  it("should throw HandledError when header fails validation", () => {
    const headers = new Headers({ "content-type": "text/plain" });
    expect(() => {
      validateHeader(headers, "content-type", (v) => v.includes("json"), 400, "Invalid type");
    }).toThrow(new HandledError(400, "Invalid type"));
  });

  it("should throw HandledError when header is missing", () => {
    const headers = new Headers();
    expect(() => {
      validateHeader(headers, "content-type", (v) => v.includes("json"), 400, "Invalid type");
    }).toThrow(new HandledError(400, "Invalid type"));
  });

  it("should throw HandledError when header is empty", () => {
    const headers = new Headers({ "content-type": "" });
    expect(() => {
      validateHeader(headers, "content-type", (v) => v.includes("json"), 400, "Invalid type");
    }).toThrow(new HandledError(400, "Invalid type"));
  });
});

describe("validateOrigin", () => {
  it("should pass validation with same-origin", () => {
    const headers = new Headers({ "Sec-Fetch-Site": "same-origin" });
    expect(() => validateOrigin(headers)).not.toThrow();
  });

  it("should pass validation with allowed origin", () => {
    const headers = new Headers({ "Origin": "https://sandbox.scirexs.dev" });
    expect(() => validateOrigin(headers)).not.toThrow();
  });

  it("should throw HandledError with invalid origin", () => {
    const headers = new Headers({ "Origin": "https://malicious.com" });
    expect(() => validateOrigin(headers)).toThrow(
      new HandledError(403, "Wrong security headers for CSRF")
    );
  });

  it("should throw HandledError with no security headers", () => {
    const headers = new Headers();
    expect(() => validateOrigin(headers)).toThrow(
      new HandledError(403, "Wrong security headers for CSRF")
    );
  });
});

describe("getStandardHeaders", () => {
  it("should return standard headers with defaults", () => {
    const result = getStandardHeaders();
    expect(result).toHaveProperty("Access-Control-Allow-Origin");
    expect(result).toHaveProperty("Content-Type", "application/json");
    expect(result).toHaveProperty("X-Content-Type-Options", "nosniff");
  });

  it("should merge custom headers with defaults", () => {
    const customHeaders = { "Custom-Header": "value" };
    const result = getStandardHeaders(customHeaders);
    expect(result).toHaveProperty("Custom-Header", "value");
    expect(result).toHaveProperty("Content-Type", "application/json");
  });

  it("should allow custom headers to override defaults", () => {
    const customHeaders = { "Content-Type": "text/plain" };
    const result = getStandardHeaders(customHeaders);
    expect(result).toHaveProperty("Content-Type", "text/plain");
  });
});

describe("getSetCookieHeader", () => {
  it("should return proper Set-Cookie header", () => {
    const result = getSetCookieHeader("session123");
    expect(result).toEqual({
      "Set-Cookie": "session=session123; HttpOnly; Secure; SameSite=Strict; Path=/; Domain=scirexs.dev"
    });
  });
});

describe("clearSetCookieHeader", () => {
  it("should return header to clear cookie", () => {
    const result = clearSetCookieHeader();
    expect(result).toEqual({
      "Set-Cookie": "session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0; Domain=scirexs.dev"
    });
  });
});

describe("extractBody", () => {
  it("should extract required properties from request body", async () => {
    const body = JSON.stringify({ username: "test", password: "secret" });
    const request = new Request("https://example.com", {
      method: "POST",
      body,
    });

    const result = await extractBody(request, "username", "password");
    expect(result).toEqual({ username: "test", password: "secret" });
  });

  it("should throw HandledError for invalid JSON", async () => {
    const request = new Request("https://example.com", {
      method: "POST",
      body: "invalid json",
    });

    await expect(extractBody(request, "username")).rejects.toThrow(
      new HandledError(400, "Request has invalid data")
    );
  });

  it("should throw HandledError for missing properties", async () => {
    const body = JSON.stringify({ username: "test" });
    const request = new Request("https://example.com", {
      method: "POST",
      body,
    });

    await expect(extractBody(request, "username", "password")).rejects.toThrow(
      new HandledError(400, "Request has invalid data")
    );
  });

  it("should throw HandledError for non-object body", async () => {
    const body = JSON.stringify(["array", "data"]);
    const request = new Request("https://example.com", {
      method: "POST",
      body,
    });

    await expect(extractBody(request, "username")).rejects.toThrow(
      new HandledError(400, "Request has invalid data")
    );
  });

  it("should throw HandledError for non-string properties", async () => {
    const body = JSON.stringify({ username: "test", age: 25 });
    const request = new Request("https://example.com", {
      method: "POST",
      body,
    });

    await expect(extractBody(request, "username", "age")).rejects.toThrow(
      new HandledError(400, "Request has invalid data")
    );
  });
});

describe("parseCookies", () => {
  it("should parse cookies from headers", () => {
    const headers = new Headers({ "Cookie": "session=abc123; theme=dark" });
    const result = parseCookies(headers);
    expect(result).toEqual({ session: "abc123", theme: "dark" });
  });

  it("should return empty object when no cookies", () => {
    const headers = new Headers();
    const result = parseCookies(headers);
    expect(result).toEqual({});
  });

  it("should handle single cookie", () => {
    const headers = new Headers({ "Cookie": "session=abc123" });
    const result = parseCookies(headers);
    expect(result).toEqual({ session: "abc123" });
  });

  it("should handle empty cookie value", () => {
    const headers = new Headers({ "Cookie": "session=; theme=dark" });
    const result = parseCookies(headers);
    expect(result).toEqual({ session: "", theme: "dark" });
  });
});

describe("getFingerprint", () => {
  it("should generate fingerprint from headers", async () => {
    const headers = new Headers({
      "CF-Connecting-IP": "192.168.1.1",
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "Accept-Language": "en-US,en;q=0.9",
      "Sec-Ch-Ua-Mobile": "?0",
      "Sec-Ch-Ua-Platform": "\"Windows\"",
      "CF-IPCountry": "US",
    });

    const result = await getFingerprint(headers);
    expect(result).toHaveLength(64); // SHA-256 hex string
    expect(typeof result).toBe("string");
  });

  it("should generate consistent fingerprint for same headers", async () => {
    const headers1 = new Headers({
      "CF-Connecting-IP": "192.168.1.1",
      "User-Agent": "Mozilla/5.0 Chrome/91.0",
    });
    const headers2 = new Headers({
      "CF-Connecting-IP": "192.168.1.1",
      "User-Agent": "Mozilla/5.0 Chrome/91.0",
    });

    const result1 = await getFingerprint(headers1);
    const result2 = await getFingerprint(headers2);
    expect(result1).toBe(result2);
  });

  it("should generate different fingerprint for different headers", async () => {
    const headers1 = new Headers({ "CF-Connecting-IP": "192.168.1.1" });
    const headers2 = new Headers({ "CF-Connecting-IP": "192.168.2.1" });

    const result1 = await getFingerprint(headers1);
    const result2 = await getFingerprint(headers2);
    expect(result1).not.toBe(result2);
  });

  it("should generate same fingerprint for ip seg4 difference", async () => {
    const headers1 = new Headers({ "CF-Connecting-IP": "192.168.1.1" });
    const headers2 = new Headers({ "CF-Connecting-IP": "192.168.1.2" });

    const result1 = await getFingerprint(headers1);
    const result2 = await getFingerprint(headers2);
    expect(result1).toBe(result2);
  });
});

describe("getIPAddress", () => {
  it("should get IP from CF-Connecting-IP header", () => {
    const headers = new Headers({ "CF-Connecting-IP": "192.168.1.1" });
    const result = getIPAddress(headers);
    expect(result).toBe("192.168.1.1");
  });

  it("should get IP from X-Forwarded-For header", () => {
    const headers = new Headers({ "X-Forwarded-For": "192.168.1.1, 10.0.0.1" });
    const result = getIPAddress(headers);
    expect(result).toBe("192.168.1.1");
  });

  it("should get IP from Forwarded header", () => {
    const headers = new Headers({ "Forwarded": "for=192.168.1.1, for=10.0.0.1" });
    const result = getIPAddress(headers);
    expect(result).toBe("for=192.168.1.1");
  });

  it("should return empty string when no IP headers", () => {
    const headers = new Headers();
    const result = getIPAddress(headers);
    expect(result).toBe("");
  });

  it("should prioritize CF-Connecting-IP over other headers", () => {
    const headers = new Headers({
      "CF-Connecting-IP": "192.168.1.1",
      "X-Forwarded-For": "10.0.0.1",
    });
    const result = getIPAddress(headers);
    expect(result).toBe("192.168.1.1");
  });
});

describe("getVerifyData", () => {
  it("should create FormData with verification parameters", () => {
    const result = getVerifyData("secret-key", "token-123", "192.168.1.1");
    expect(result).toBeInstanceOf(FormData);
    expect(result.get("secret")).toBe("secret-key");
    expect(result.get("response")).toBe("token-123");
    expect(result.get("remoteip")).toBe("192.168.1.1");
  });
});

describe("sendMail", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should send email using Resend", async () => {
    const mockSend = vi.fn().mockResolvedValue({ id: "test-id" });
    (Resend as any).mockImplementation(() => ({
      emails: { send: mockSend },
    }));

    const payload = { from: "test@example.com", to: "user@example.com", subject: "Test", text: "Mail body" };
    await sendMail("api-key", payload);

    expect(Resend).toHaveBeenCalledWith("api-key");
    expect(mockSend).toHaveBeenCalledWith(payload);
  });

  it("should handle email sending errors", async () => {
    const mockSend = vi.fn().mockRejectedValue(new Error("Email failed"));
    (Resend as any).mockImplementation(() => ({
      emails: { send: mockSend },
    }));

    const payload = { from: "test@example.com", to: "user@example.com", subject: "Test", text: "Mail body" };
    await expect(sendMail("api-key", payload)).rejects.toThrow("Email failed");
  });
});

describe("createSignupMail", () => {
  it("should create signup email payload", () => {
    const result = createSignupMail("user@example.com", "ABC123");
    expect(result).toEqual({
      from: "NoReply <no_reply@scirexs.dev>",
      to: "user@example.com",
      subject: "[Account Registration] Email Address Verification",
      text: expect.stringContaining("ABC123"),
    });
    expect(result.text).toContain("verify your email address");
  });
});

describe("genVerifyCode", () => {
  it("should generate code of specified length", () => {
    const result = genVerifyCode(6);
    expect(result).toHaveLength(6);
  });

  it("should generate different codes on multiple calls", () => {
    const code1 = genVerifyCode(8);
    const code2 = genVerifyCode(8);
    // This might occasionally fail due to randomness, but very unlikely
    expect(code1).not.toBe(code2);
  });

  it("should only contain valid characters", () => {
    const result = genVerifyCode(100);
    const validChars = /^[ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstvwxyz23456789]+$/;
    expect(result).toMatch(validChars);
  });

  it("should handle zero length", () => {
    const result = genVerifyCode(0);
    expect(result).toBe("");
  });
});

describe("genUUID", () => {
  it("should generate UUID", () => {
    const result = genUUID();
    expect(result).toBe("test-uuid-1234");
  });
});

describe("Durable Object getters", () => {
  const mockEnv: MockEnv = {
    SIGNUP_VERIFY: {
      get: vi.fn().mockReturnValue("signup-stub"),
      idFromName: vi.fn().mockReturnValue("signup-id"),
    },
    LOGIN_REQUEST: {
      get: vi.fn().mockReturnValue("login-stub"),
      idFromName: vi.fn().mockReturnValue("login-id"),
    },
    USER_SESSION: {
      get: vi.fn().mockReturnValue("session-stub"),
      idFromName: vi.fn().mockReturnValue("session-id"),
    },
    RATE_LIMIT: {
      get: vi.fn().mockReturnValue("rate-limit-stub"),
      idFromName: vi.fn().mockReturnValue("rate-limit-id"),
    },
  };

  it("should get DOSignup stub", () => {
    const result = getDOSignup(mockEnv as any);
    expect(mockEnv.SIGNUP_VERIFY.idFromName).toHaveBeenCalledWith("signup");
    expect(mockEnv.SIGNUP_VERIFY.get).toHaveBeenCalledWith("signup-id");
    expect(result).toBe("signup-stub");
  });

  it("should get DOLogin stub", () => {
    const result = getDOLogin(mockEnv as any);
    expect(mockEnv.LOGIN_REQUEST.idFromName).toHaveBeenCalledWith("login");
    expect(mockEnv.LOGIN_REQUEST.get).toHaveBeenCalledWith("login-id");
    expect(result).toBe("login-stub");
  });

  it("should get DOSession stub", () => {
    const result = getDOSession(mockEnv as any);
    expect(mockEnv.USER_SESSION.idFromName).toHaveBeenCalledWith("session");
    expect(mockEnv.USER_SESSION.get).toHaveBeenCalledWith("session-id");
    expect(result).toBe("session-stub");
  });

  it("should get DORateLimit stub", () => {
    const result = getDORateLimit(mockEnv as any);
    expect(mockEnv.RATE_LIMIT.idFromName).toHaveBeenCalledWith("rate_limit");
    expect(mockEnv.RATE_LIMIT.get).toHaveBeenCalledWith("rate-limit-id");
    expect(result).toBe("rate-limit-stub");
  });
});
