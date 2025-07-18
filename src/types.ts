export type { ResponseHeaders, TurnstileResponse, SandboxUsers, RowCount, SignupVerify, LoginRequest, LoginSession, RateLimit, KeyPair };
import type { KeyPair } from "@scirexs/srp6a/server";

interface ResponseHeaders {
  [key: string]: string;
}
interface TurnstileResponse {
  success: boolean;
  "error-codes": string[];
  challenge_ts?: string;
  hostname?: string;
  action?: string;
  cdata?: string;
  metadata?: Record<string, string>;
}
interface SandboxUsers {
  userid: string;
  username: string;
  salt: string;
  verifier: string;
  status: "pending" | "active";
  create_date: string;
  update_date: string;
  last_login?: string;
}
interface RowCount {
  count: number;
}

interface SignupVerify {
  username: string;
  code: string;
  count: number;
  expire: number;
}
interface LoginRequest {
  userid: string;
  username: string;
  salt: string;
  verifier: string;
  client: string;
  pair: KeyPair;
  expire: number;
}
interface LoginSession {
  userid: string;
  refresh: number;
  expire: number;
  keep: boolean;
  fingerprint: string;
}
interface RateLimit {
  count: number;
  expire: number;
}
