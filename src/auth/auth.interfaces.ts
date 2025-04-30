import { IUser, ICreateUserData } from "../user/user.interfaces.js";

export interface TokenPayload {
  token: string;
  expires: Date;
}

export interface AccessAndRefreshTokens {
  access: TokenPayload;
  refresh: TokenPayload;
}

export interface UserCredentials {
  email: string;
  password: string;
}
