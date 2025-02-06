import { ApisauceInstance } from "apisauce";
import { AccessAndRefreshTokens, UserCredentials } from "./auth.interfaces.js";
import * as storage from "../storage/storage.service.js";
import * as key from "../key/key.service.js";
import nacl from "tweetnacl";
import pkg from "tweetnacl-util";

const { encodeBase64 } = pkg;

export const validateEmailAndPassword = async ({
  email,
  password,
}: {
  email: string;
  password: string;
}) => {
  let encryptedKeyObject;

  try {
    encryptedKeyObject = await storage.loadKey({
      identifier: email,
      type: "identity.public",
    });
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`No account found with that email. ${error.message}`);
    } else {
      throw new Error("No account found with that email.");
    }
  }

  try {
    await key.decryptKey({
      encryptedKeyObject,
      password,
    });
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Incorrect password. ${error.message}`);
    } else {
      throw new Error("Incorrect password.");
    }
  }
};

class AuthService {
  private api: ApisauceInstance;
  private logger: any;
  public verbose: boolean;

  constructor(apiInstance: ApisauceInstance, log: any, verb: boolean) {
    this.api = apiInstance;
    this.logger = log;
    this.verbose = verb;
  }

  async loginWithToken({
    email,
    token,
  }: {
    email?: string;
    token?: string;
  }): Promise<AccessAndRefreshTokens | null> {
    let refreshToken = token;
    if (!refreshToken && email) {
      try {
        const foundToken = storage.loadToken({ email, type: "refresh" });
        refreshToken = foundToken !== null ? foundToken : undefined;
      } catch {
        return null; //no token found
      }
    }
    if (!refreshToken) {
      return null;
    }

    if (this.verbose) {
      this.logger.log(`Using refresh token: ${refreshToken}`);
    }

    // Temporarily remove the Authorization header
    const originalAuthHeader =
      this.api.axiosInstance.defaults.headers.common["Authorization"];
    this.api.setHeader("Authorization", "");

    const response = await this.api.post<AccessAndRefreshTokens>(
      "/v1/auth/refresh-tokens",
      { refreshToken }
    );

    // Restore the header after the refresh call
    if (originalAuthHeader) {
      if (typeof originalAuthHeader === "string") {
        this.api.setHeader("Authorization", originalAuthHeader);
      }
    }

    if (response.status && response.status >= 200 && response.status < 300) {
      const newAccessToken = response.data?.access.token;
      if (newAccessToken) {
        this.api.setHeader("Authorization", `Bearer ${newAccessToken}`);
      }
      if (response.data) {
        return response.data;
      } else {
        return null; // Return null on invalid token
      }
    } else {
      return null; // Return null on invalid token
    }
  }

  async loginWithKey({
    email,
    password,
  }: {
    email: string;
    password: string;
  }): Promise<AccessAndRefreshTokens> {
    try {
      const user = storage.loadUser({ email });

      const { ownerGuardianId } = user;
      const nonceResponse = await this.api.post<{ nonce: string }>(
        "/v1/auth/nonce",
        { email }
      );
      if (!nonceResponse.data || !nonceResponse.data.nonce) {
        throw new Error("Failed to get nonce.");
      }
      const nonce = nonceResponse.data.nonce;

      const privateKeyObject = storage.loadKey({
        identifier: email,
        type: "identity.private",
      });

      const privateKey = await key.decryptKey({
        encryptedKeyObject: privateKeyObject,
        password,
      });
      const privateKeyBuffer = Buffer.from(privateKey, "base64");

      const message = Buffer.from(nonce, "hex");
      const signature = nacl.sign.detached(message, privateKeyBuffer);
      const signatureBase64 = encodeBase64(signature);

      const loginResponse = await this.api.post<AccessAndRefreshTokens>(
        "/v1/auth/loginChallenge",
        { email, signature: signatureBase64 }
      );
      if (
        loginResponse.status &&
        loginResponse.status >= 200 &&
        loginResponse.status < 300
      ) {
        const newAccessToken = loginResponse.data?.access.token;
        if (newAccessToken) {
          this.api.setHeader("Authorization", `Bearer ${newAccessToken}`);
        }
        if (loginResponse.data) {
          return loginResponse.data;
        } else {
          throw new Error("Failed to login: No data received.");
        }
      } else {
        throw new Error(`Failed to login: ${loginResponse.problem}`);
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      throw new Error(errorMessage);
    }
  }

  async login({
    email,
    password,
  }: UserCredentials): Promise<AccessAndRefreshTokens> {
    let authTokens = await this.loginWithToken({ email });
    if (!authTokens) {
      authTokens = await this.loginWithKey({ email, password });
    }
    if (authTokens) {
      storage.saveTokens({ authTokens, email });
      return authTokens;
    }
    throw new Error("Failed to login.");
  }
}

export default AuthService;
