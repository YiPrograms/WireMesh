import { describe, expect, it } from "vitest";
import { derivePublicKey } from "./keys";

describe("WireGuard browser keys", () => {
  it("derives the RFC 7748 X25519 public key without leaving the browser", () => {
    const privateKey = btoa(String.fromCharCode(...new Uint8Array(32).fill(1)));
    expect(derivePublicKey(privateKey)).toBe(
      "pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogk=",
    );
  });
});
