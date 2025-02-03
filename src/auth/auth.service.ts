import { ApisauceInstance } from "apisauce";
import { AccessAndRefreshTokens, UserCredentials } from "./auth.interfaces.js";
import { IUser } from "../user/user.interfaces.js";
import { storage } from "../storage/index.js";
import { key } from "../key/index.js";
import crypto from "crypto";

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
      type: "public",
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
  }): Promise<AccessAndRefreshTokens> {
    const refreshToken =
      token || (email ? storage.loadToken({ email, type: "refresh" }) : null);

    if (!refreshToken) {
      throw new Error("No refresh token provided.");
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
        throw new Error("Failed to refresh tokens: No data received.");
      }
    } else {
      throw new Error(`Failed to refresh tokens: ${response.problem}`);
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
        { ownerGuardianId }
      );
      if (!nonceResponse.data || !nonceResponse.data.nonce) {
        throw new Error("Failed to get nonce.");
      }
      const nonce = nonceResponse.data.nonce;
      console.log("nonce", nonce);

      const privateKeyObject = storage.loadKey({
        identifier: email,
        type: "private",
      });
      const privateKey = await key.decryptKey({
        encryptedKeyObject: privateKeyObject,
        password,
      });

      const privateKeyBuffer = Buffer.from(privateKey, "base64");
      console.log("privateKeyBuffer", privateKeyBuffer);
      const signature = crypto.sign(null, Buffer.from(nonce, "hex"), {
        key: privateKeyBuffer,
        format: "der",
        type: "pkcs8",
      });

      console.log("signature", signature);
      const loginResponse = await this.api.post<AccessAndRefreshTokens>(
        "/v1/auth/loginChallenge",
        { user, signature: signature.toString("base64") }
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
    try {
      let authTokens = await this.loginWithToken({ email });
      if (!authTokens) {
        authTokens = await this.loginWithKey({ email, password });
      }
      if (authTokens) {
        storage.saveTokens({ authTokens, email });
        return authTokens;
      } else {
        throw new Error("Failed to login.");
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      throw new Error(errorMessage);
    }
  }
}

export default AuthService;
