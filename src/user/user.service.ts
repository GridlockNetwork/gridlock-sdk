import { ApisauceInstance } from "apisauce";
import { storage } from "../storage/index.js";
import { key } from "../key/index.js";
import { IRegisterResponse, IUser } from "./user.interfaces.js";

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
    await key.generateE2EKeys(user.email, password);
    await key.generateSigningKey(user.email, password);
    return response.data;
  }

  const errorData = response.data as { message?: string } | undefined;
  const message = errorData?.message || response.problem || "Unknown error";
  throw new Error(message);
}

export async function recover(
  api: ApisauceInstance,
  email: string,
  password: string
): Promise<any> {
  await key.generateE2EKeys(email, password);
  await key.generateRecoveryKey(email, password);
  console.log("email stuffs", email, password);
  const response = await api.get<IUser>(`/v1/users/${email}`);
  if (!response.ok || !response.data) {
    const errorData = response.data as { message?: string } | undefined;
    const message = errorData?.message || response.problem || "Unknown error";
    throw new Error(message);
  }
  const user = response.data;
  const encryptedPublicKey = storage.loadKey({
    identifier: email,
    type: "public",
  });
  const clientPublicKey = await key.decryptKey({
    encryptedKeyObject: encryptedPublicKey,
    password,
  });
  const keyBundle = await key.generateKeyBundle({
    user,
    password,
    type: "recovery",
  });
  const recoverResponse = await api.post("/v1/users/recover", {
    email,
    clientPublicKey,
    keyBundle,
  });

  if (!recoverResponse.ok) {
    const errorData = recoverResponse.data as { message?: string } | undefined;
    const message =
      errorData?.message || recoverResponse.problem || "Unknown error";
    throw new Error(message);
  }

  console.log("Key Bundle:", keyBundle);
  return { user, clientPublicKey, keyBundle };
}
