import { IUser, IRegisterData } from "./user.type";

export interface ILoginResponse {
  authTokens: {
    access: {
      token: string;
      expires: string;
    };
    refresh: {
      token: string;
      expires: string;
    };
  };
}

export interface IRegisterResponse {
  user: IUser;
  authTokens: ILoginResponse;
}
