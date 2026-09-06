import { SignJWT, jwtVerify, type JWTPayload } from "jose";

/** Every artefact this server hands out is an HS256 JWT tagged with a `typ`
 *  so one kind can never be replayed as another. Nothing is stored server-side. */
export type TokenType = "client" | "authreq" | "code" | "access" | "refresh";

export class Tokens {
  constructor(
    private key: Uint8Array,
    private issuer: string,
  ) {}

  async sign(typ: TokenType, claims: JWTPayload, ttlSec: number): Promise<string> {
    return new SignJWT({ ...claims, typ })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer(this.issuer)
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .setExpirationTime(Math.floor(Date.now() / 1000) + ttlSec)
      .sign(this.key);
  }

  /** Returns the payload, or undefined if the token is invalid, expired or of another type. */
  async verify(typ: TokenType, token: string): Promise<JWTPayload | undefined> {
    try {
      const { payload } = await jwtVerify(token, this.key, { issuer: this.issuer, algorithms: ["HS256"] });
      return payload.typ === typ ? payload : undefined;
    } catch {
      return undefined;
    }
  }
}
