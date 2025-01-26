import { IUser, IRegisterData } from "./user.type";

export interface TokenPayload {
  token: string;
  expires: Date;
}

export interface AccessAndRefreshTokens {
  access: TokenPayload;
  refresh: TokenPayload;
}

export interface IRegisterResponse {
  user: IUser;
  authTokens: AccessAndRefreshTokens;
}
