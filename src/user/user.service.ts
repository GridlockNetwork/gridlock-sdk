import { ApisauceInstance } from "apisauce";
import { storage } from "../storage/index.js";
import { key } from "../key/index.js";
import { ICreateUserData, IRegisterResponse } from "./user.interfaces.js";

export async function createUser(
  api: ApisauceInstance,
  name: string,
  email: string,
  password: string
): Promise<IRegisterResponse> {
  const response = await api.post<IRegisterResponse>("/v1/auth/register", {
    name,
    email,
  });

  if (response.ok && response.data) {
    const { user, authTokens } = response.data;
    storage.saveTokens({ authTokens, email: user.email });
    storage.saveUser({ user });
    await key.generateUserKeys(user.email, password);
    return response.data;
  }

  const errorData = response.data as { message?: string } | undefined;
  const message = errorData?.message || response.problem || "Unknown error";
  throw new Error(message);
}
