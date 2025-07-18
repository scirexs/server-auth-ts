import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  isRateLimited,
  validateHeaders,
  verifyTurnstile,
  createJSONResponse,
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
} from "../src/processes.js";
import { MAX_RATE_LIMIT, MAX_VERIFY_LIMIT, TURNSTILE_URL } from "../src/constants.js";
import { HandledError } from "../src/utils.js";

// Mock external dependencies
vi.mock("@scirexs/srp6a/server", () => ({
  addRandomDelay: vi.fn(),
  authenticate: vi.fn(),
  createDummyHello: vi.fn(),
  createServerHello: vi.fn(),
  getDefaultConfig: vi.fn(),
}));

vi.mock("../src/utils.js", () => ({
  HandledError: class extends Error {
    constructor(public status: number, message: string) {
      super(message);
    }
  },
  validateHeader: vi.fn(),
  validateOrigin: vi.fn(),
  getStandardHeaders: vi.fn(),
  getSetCookieHeader: vi.fn(),
  clearSetCookieHeader: vi.fn(),
  parseCookies: vi.fn(),
  getFingerprint: vi.fn(),
  getIPAddress: vi.fn(),
  getVerifyData: vi.fn(),
  getDORateLimit: vi.fn(),
  createSignupMail: vi.fn(),
  sendMail: vi.fn(),
  genUUID: vi.fn(),
}));

vi.mock("../src/constants.js", () => ({
  MAX_RATE_LIMIT: 20,
  MAX_VERIFY_LIMIT: 5,
  TURNSTILE_URL: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
}));

describe("processes.ts", () => {
  let mockEnv: any;
  let mockHeaders: Headers;
  let mockDurableObjectStub: any;

  beforeEach(() => {
    mockEnv = {
      TURNSTILE_SECRET_KEY: "test-secret",
      RESEND_API_KEY: "test-resend-key",
    };

    mockHeaders = new Headers({
      "Content-Type": "application/json",
      "Content-Length": "100",
      "Accept": "application/json",
    });

    mockDurableObjectStub = {
      count: vi.fn(),
      store: vi.fn(),
      read: vi.fn(),
      delete: vi.fn(),
      countup: vi.fn(),
      start: vi.fn(),
      verify: vi.fn(),
    };

    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("isRateLimited", () => {
    it("should return true when rate limit is exceeded", async () => {
      const { getIPAddress, getDORateLimit } = await import("../src/utils.js");
      vi.mocked(getIPAddress).mockReturnValue("192.168.1.1");
      vi.mocked(getDORateLimit).mockReturnValue(mockDurableObjectStub);
      mockDurableObjectStub.count.mockResolvedValue(25);

      const result = await isRateLimited(mockHeaders, mockEnv);
      expect(result).toBe(true);
    });

    it("should return false when rate limit is not exceeded", async () => {
      const { getIPAddress, getDORateLimit } = await import("../src/utils.js");
      vi.mocked(getIPAddress).mockReturnValue("192.168.1.1");
      vi.mocked(getDORateLimit).mockReturnValue(mockDurableObjectStub);
      mockDurableObjectStub.count.mockResolvedValue(10);

      const result = await isRateLimited(mockHeaders, mockEnv);
      expect(result).toBe(false);
    });

    it("should handle unknown IP with reduced limit", async () => {
      const { getIPAddress, getDORateLimit } = await import("../src/utils.js");
      vi.mocked(getIPAddress).mockReturnValue("");
      vi.mocked(getDORateLimit).mockReturnValue(mockDurableObjectStub);
      mockDurableObjectStub.count.mockResolvedValue(15);

      const result = await isRateLimited(mockHeaders, mockEnv);
      expect(result).toBe(true);
    });
  });

  describe("validateHeaders", () => {
    it("should pass validation with correct headers", async () => {
      const { validateHeader, validateOrigin } = await import("../src/utils.js");
      vi.mocked(validateHeader).mockImplementation(() => {});
      vi.mocked(validateOrigin).mockImplementation(() => {});

      expect(() => validateHeaders(mockHeaders)).not.toThrow();
    });

    it("should throw error for invalid headers", async () => {
      const { validateHeader, validateOrigin } = await import("../src/utils.js");
      vi.mocked(validateHeader).mockImplementation(() => {
        throw new HandledError(413, "Request body too large");
      });

      expect(() => validateHeaders(mockHeaders)).toThrow(HandledError);
    });
  });

  describe("verifyTurnstile", () => {
    // it("should verify turnstile successfully", async () => {
    //   const { getIPAddress, getVerifyData } = await import("../src/utils.js");
    //   vi.mocked(getIPAddress).mockReturnValue("192.168.1.1");
    //   vi.mocked(getVerifyData).mockReturnValue(new FormData());

    //   const mockResponse = {
    //     json: vi.fn().mockResolvedValue({ success: true }),
    //   };
    //   vi.mocked(fetch).mockResolvedValue(mockResponse as any);

    //   await expect(verifyTurnstile(mockHeaders, "test-token", "test-secret")).resolves.not.toThrow();
    // });

    // it("should throw error when turnstile verification fails", async () => {
    //   const { getIPAddress, getVerifyData } = await import("../src/utils.js");
    //   vi.mocked(getIPAddress).mockReturnValue("192.168.1.1");
    //   vi.mocked(getVerifyData).mockReturnValue(new FormData());

    //   const mockResponse = {
    //     json: vi.fn().mockResolvedValue({ success: false }),
    //   };
    //   vi.mocked(fetch).mockResolvedValue(mockResponse as any);

    //   await expect(verifyTurnstile(mockHeaders, "test-token", "test-secret")).rejects.toThrow(HandledError);
    // });

    it("should throw error when token or IP is missing", async () => {
      const { getIPAddress } = await import("../src/utils.js");
      vi.mocked(getIPAddress).mockReturnValue("");

      await expect(verifyTurnstile(mockHeaders, "", "test-secret")).rejects.toThrow(HandledError);
    });
  });

  describe("createJSONResponse", () => {
    it("should create JSON response with default status", async () => {
      const { getStandardHeaders } = await import("../src/utils.js");
      vi.mocked(getStandardHeaders).mockReturnValue({ "Content-Type": "application/json" });

      const body = { success: true };
      const response = createJSONResponse(body);

      expect(response.status).toBe(200);
      expect(response.headers.get("Content-Type")).toBe("application/json");
    });

    it("should create JSON response with custom status and headers", async () => {
      const { getStandardHeaders } = await import("../src/utils.js");
      vi.mocked(getStandardHeaders).mockReturnValue({ "Content-Type": "application/json" });

      const body = { success: true };
      const customHeaders = { "X-Custom": "value" };
      const response = createJSONResponse(body, 201, customHeaders);

      expect(response.status).toBe(201);
    });
  });

  describe("responseDummySignup", () => {
    it("should return dummy signup response", async () => {
      const { addRandomDelay } = await import("@scirexs/srp6a/server");
      const { genUUID } = await import("../src/utils.js");
      vi.mocked(addRandomDelay).mockResolvedValue(undefined);
      vi.mocked(genUUID).mockReturnValue("mock-uuid");

      const response = await responseDummySignup();
      expect(response.status).toBe(201);
      const body = await response.json() as { success: boolean, userid: string };
      expect(body.success).toBe(true);
      expect(body.userid).toBe("mock-uuid");
    });
  });

  describe("sendVerifyCode", () => {
    it("should send verification code successfully", async () => {
      const { createSignupMail, sendMail } = await import("../src/utils.js");
      mockDurableObjectStub.store.mockResolvedValue("ABC123");
      vi.mocked(createSignupMail).mockReturnValue({ from: "from@example.com", to: "test@example.com", subject: "Test", text: "Mail body" });
      vi.mocked(sendMail).mockResolvedValue(undefined);

      await sendVerifyCode(mockDurableObjectStub, "user123", "test@example.com", "api-key");

      expect(mockDurableObjectStub.store).toHaveBeenCalledWith("user123", "test@example.com");
      expect(sendMail).toHaveBeenCalled();
    });
  });

  describe("resendVerifyCode", () => {
    it("should resend verification code successfully", async () => {
      const { createSignupMail, sendMail } = await import("../src/utils.js");
      mockDurableObjectStub.read.mockResolvedValue({
        username: "test@example.com",
        code: "ABC123",
        count: 1,
        expire: Date.now() + 60000,
      });
      mockDurableObjectStub.store.mockResolvedValue("DEF456");
      vi.mocked(createSignupMail).mockReturnValue({ from: "from@example.com", to: "test@example.com", subject: "Test", text: "Mail body" });
      vi.mocked(sendMail).mockResolvedValue(undefined);

      await resendVerifyCode(mockDurableObjectStub, "user123", "api-key");

      expect(mockDurableObjectStub.read).toHaveBeenCalledWith("user123");
      expect(sendMail).toHaveBeenCalled();
    });

    it("should throw error when user not found", async () => {
      mockDurableObjectStub.read.mockResolvedValue(null);

      await expect(resendVerifyCode(mockDurableObjectStub, "user123", "api-key")).rejects.toThrow(HandledError);
    });
  });

  describe("verifyCode", () => {
    it("should verify code successfully", async () => {
      const mockUser = {
        username: "test@example.com",
        code: "ABC123",
        count: 1,
        expire: Date.now() + 60000,
      };
      mockDurableObjectStub.read.mockResolvedValue(mockUser);
      mockDurableObjectStub.delete.mockResolvedValue(undefined);

      const result = await verifyCode(mockDurableObjectStub, "user123", "ABC123");
      expect(result).toBe(true);
      expect(mockDurableObjectStub.delete).toHaveBeenCalledWith("user123");
    });

    it("should throw error when user not found", async () => {
      mockDurableObjectStub.read.mockResolvedValue(null);

      await expect(verifyCode(mockDurableObjectStub, "user123", "ABC123")).rejects.toThrow(HandledError);
    });

    it("should throw error when too many failed attempts", async () => {
      const mockUser = {
        username: "test@example.com",
        code: "ABC123",
        count: 6,
        expire: Date.now() + 60000,
      };
      mockDurableObjectStub.read.mockResolvedValue(mockUser);

      await expect(verifyCode(mockDurableObjectStub, "user123", "ABC123")).rejects.toThrow(HandledError);
      expect(mockDurableObjectStub.delete).toHaveBeenCalledWith("user123");
    });

    it("should throw error when code is expired", async () => {
      const mockUser = {
        username: "test@example.com",
        code: "ABC123",
        count: 1,
        expire: Date.now() - 60000,
      };
      mockDurableObjectStub.read.mockResolvedValue(mockUser);

      await expect(verifyCode(mockDurableObjectStub, "user123", "ABC123")).rejects.toThrow(HandledError);
      expect(mockDurableObjectStub.delete).toHaveBeenCalledWith("user123");
    });

    it("should increment count for wrong code", async () => {
      const mockUser = {
        username: "test@example.com",
        code: "ABC123",
        count: 1,
        expire: Date.now() + 60000,
      };
      mockDurableObjectStub.read.mockResolvedValue(mockUser);
      mockDurableObjectStub.countup.mockResolvedValue(undefined);

      await expect(verifyCode(mockDurableObjectStub, "user123", "WRONG")).rejects.toThrow(HandledError);
      expect(mockDurableObjectStub.countup).toHaveBeenCalledWith("user123", mockUser);
    });
  });

  describe("responseDummyHello", () => {
    it("should return dummy hello response", async () => {
      const { createDummyHello, getDefaultConfig } = await import("@scirexs/srp6a/server");
      // const { addRandomDelay } = await import("@scirexs/srp6a/server");
      const { genUUID } = await import("../src/utils.js");

      vi.mocked(createDummyHello).mockReturnValue({ server: "dummy-B", salt: "dummy-salt" });
      // vi.mocked(getDefaultConfig).mockReturnValue({});
      // vi.mocked(addRandomDelay).mockResolvedValue(undefined);
      vi.mocked(genUUID).mockReturnValue("mock-request-id");

      const response = await responseDummyHello();
      const body = await response.json() as Record<string, string>;

      expect(body.server).toBe("dummy-B");
      expect(body.salt).toBe("dummy-salt");
      expect(body.requestId).toBe("mock-request-id");
    });
  });

  describe("prepareLogin", () => {
    it("should prepare login successfully", async () => {
      const { createServerHello, getDefaultConfig } = await import("@scirexs/srp6a/server");
      const mockRow = {
        userid: "user123",
        username: "test@example.com",
        salt: "test-salt",
        verifier: "test-verifier",
        status: "active" as const,
        create_date: "2023-01-01",
        update_date: "2023-01-01",
      };
      const mockHello = { server: "server-B", salt: "server-salt" };
      const mockPair = { private: "private-key", public: "public-key" };

      vi.mocked(createServerHello).mockResolvedValue([mockHello, mockPair]);
      // vi.mocked(getDefaultConfig).mockReturnValue({});
      mockDurableObjectStub.store.mockResolvedValue("request-id");

      const result = await prepareLogin(mockDurableObjectStub, mockRow, "test@example.com", "client-A");

      expect(result.server).toBe("server-B");
      expect(result.salt).toBe("server-salt");
      expect(result.requestId).toBe("request-id");
    });
  });

  describe("loadPrepare", () => {
    it("should load prepare data successfully", async () => {
      const mockData = {
        userid: "user123",
        username: "test@example.com",
        salt: "test-salt",
        verifier: "test-verifier",
        client: "client-A",
        pair: { private: "private-key", public: "public-key" },
        expire: Date.now() + 60000,
      };
      mockDurableObjectStub.read.mockResolvedValue(mockData);

      const result = await loadPrepare(mockDurableObjectStub, "request-id");
      expect(result).toEqual(mockData);
    });

    it("should throw error when request not found", async () => {
      mockDurableObjectStub.read.mockResolvedValue(null);

      await expect(loadPrepare(mockDurableObjectStub, "request-id")).rejects.toThrow(HandledError);
    });

    it("should throw error when request is expired", async () => {
      const mockData = {
        userid: "user123",
        username: "test@example.com",
        salt: "test-salt",
        verifier: "test-verifier",
        client: "client-A",
        pair: { private: "private-key", public: "public-key" },
        expire: Date.now() - 60000,
      };
      mockDurableObjectStub.read.mockResolvedValue(mockData);

      await expect(loadPrepare(mockDurableObjectStub, "request-id")).rejects.toThrow(HandledError);
    });
  });

  describe("authUser", () => {
    it("should authenticate user successfully", async () => {
      const { authenticate, getDefaultConfig } = await import("@scirexs/srp6a/server");
      const mockData = {
        userid: "user123",
        username: "test@example.com",
        salt: "test-salt",
        verifier: "test-verifier",
        client: "client-A",
        pair: { private: "private-key", public: "public-key" },
        expire: Date.now() + 60000,
      };
      const mockResult = { success: true, evidence: "server-proof" };

      vi.mocked(authenticate).mockResolvedValue(mockResult);
      // vi.mocked(getDefaultConfig).mockReturnValue({});

      const result = await authUser(mockData, "request-id", "client-evidence");

      expect(result.success).toBe(true);
      expect(result.evidence).toBe("server-proof");
      expect(result.requestId).toBe("request-id");
    });
  });

  describe("getSessionHeader", () => {
    it("should get session header with Headers object", async () => {
      const { getFingerprint, getSetCookieHeader } = await import("../src/utils.js");
      vi.mocked(getFingerprint).mockResolvedValue("fingerprint-hash");
      vi.mocked(getSetCookieHeader).mockReturnValue({ "Set-Cookie": "session=session-id" });
      mockDurableObjectStub.start.mockResolvedValue("session-id");

      const result = await getSessionHeader(mockDurableObjectStub, mockHeaders, "user123");
      expect(result).toEqual({ "Set-Cookie": "session=session-id" });
    });

    it("should get session header with fingerprint string", async () => {
      const { getSetCookieHeader } = await import("../src/utils.js");
      vi.mocked(getSetCookieHeader).mockReturnValue({ "Set-Cookie": "session=session-id" });
      mockDurableObjectStub.start.mockResolvedValue("session-id");

      const result = await getSessionHeader(mockDurableObjectStub, "fingerprint-hash", "user123");
      expect(result).toEqual({ "Set-Cookie": "session=session-id" });
    });
  });

  describe("getEmptySessionHeader", () => {
    it("should get empty session header", async () => {
      const { parseCookies, clearSetCookieHeader } = await import("../src/utils.js");
      vi.mocked(parseCookies).mockReturnValue({ session: "session-id" });
      vi.mocked(clearSetCookieHeader).mockReturnValue({ "Set-Cookie": "session=; Max-Age=0" });
      mockDurableObjectStub.delete.mockResolvedValue(undefined);

      const result = await getEmptySessionHeader(mockDurableObjectStub, mockHeaders);
      expect(result).toEqual({ "Set-Cookie": "session=; Max-Age=0" });
      expect(mockDurableObjectStub.delete).toHaveBeenCalledWith("session-id");
    });
  });

  describe("verifySession", () => {
    it("should verify session successfully", async () => {
      const { parseCookies, getFingerprint } = await import("../src/utils.js");
      vi.mocked(parseCookies).mockReturnValue({ session: "session-id" });
      vi.mocked(getFingerprint).mockResolvedValue("fingerprint-hash");
      mockDurableObjectStub.verify.mockResolvedValue({ userid: "user123", keep: true });

      const result = await verifySession(mockDurableObjectStub, mockHeaders);
      expect(result).toEqual(["user123", undefined]);
    });

    it("should return empty string when no session cookie", async () => {
      const { parseCookies } = await import("../src/utils.js");
      vi.mocked(parseCookies).mockReturnValue({});

      const result = await verifySession(mockDurableObjectStub, mockHeaders);
      expect(result).toEqual([""]);
    });

    it("should return empty string when session verification fails", async () => {
      const { parseCookies, getFingerprint } = await import("../src/utils.js");
      vi.mocked(parseCookies).mockReturnValue({ session: "session-id" });
      vi.mocked(getFingerprint).mockResolvedValue("fingerprint-hash");
      mockDurableObjectStub.verify.mockResolvedValue(null);

      const result = await verifySession(mockDurableObjectStub, mockHeaders);
      expect(result).toEqual([""]);
    });

    it("should return new session header when keep is false", async () => {
      const { parseCookies, getFingerprint, getSetCookieHeader } = await import("../src/utils.js");
      vi.mocked(parseCookies).mockReturnValue({ session: "session-id" });
      vi.mocked(getFingerprint).mockResolvedValue("fingerprint-hash");
      vi.mocked(getSetCookieHeader).mockReturnValue({ "Set-Cookie": "session=new-session-id" });
      mockDurableObjectStub.verify.mockResolvedValue({ userid: "user123", keep: false });
      mockDurableObjectStub.start.mockResolvedValue("new-session-id");

      const result = await verifySession(mockDurableObjectStub, mockHeaders);
      expect(result).toEqual(["user123", { "Set-Cookie": "session=new-session-id" }]);
    });
  });
});
