import { ApisauceInstance } from "apisauce";
import * as storage from "../storage/storage.service.js";
import * as key from "../key/key.service.js";
import { IRegisterResponse, IUser } from "./user.interfaces.js";

export async function createUser(
  api: ApisauceInstance,
  name: string,
  email: string,
  password: string
): Promise<IRegisterResponse> {
  const { publicKey: identityPublicKey } = await key.generateIdentityKeys(
    email,
    password
  );

  const { publicKey: e2ePublicKey } = await key.generateE2EKeys(
    email,
    password
  );

  await key.generateSigningKey(email, password);

  const response = await api.post<IRegisterResponse>("/v1/auth/register", {
    name,
    email,
    identityPublicKey,
    e2ePublicKey,
  });

  if (response.ok && response.data) {
    const { user, authTokens } = response.data;
    storage.saveTokens({ authTokens, email: user.email });
    storage.saveUser({ user });

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
  const response = await api.get<IUser>(`/v1/users/${email}`);
  if (!response.ok || !response.data) {
    const errorData = response.data as { message?: string } | undefined;
    const message = errorData?.message || response.problem || "Unknown error";
    throw new Error(message);
  }
  const user = response.data;
  const encryptedPublicKey = storage.loadKey({
    identifier: email,
    type: "e2e.public",
  });
  const e2ePublicKey = await key.decryptKey({
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
    clientPublicKey: e2ePublicKey,
    keyBundle,
  });

  if (!recoverResponse.ok) {
    const errorData = recoverResponse.data as { message?: string } | undefined;
    const message =
      errorData?.message || recoverResponse.problem || "Unknown error";
    throw new Error(message);
  }

  return { user, e2ePublicKey, keyBundle };
}
