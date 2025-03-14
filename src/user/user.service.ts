import { ApisauceInstance } from "apisauce";
import * as storage from "../storage/storage.service.js";
import * as key from "../key/key.service.js";
import { IRegisterResponse, IUser } from "./user.interfaces.js";

export async function createUser(
  api: ApisauceInstance,
  name: string,
  email: string,
  password: string,
  saveCredentials: boolean = false
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

    if (saveCredentials) {
      storage.saveStoredCredentials({ email, password });
    }

    return response.data;
  }

  const errorData = response.data as { message?: string } | undefined;
  const message = errorData?.message || response.problem || "Unknown error";
  throw new Error(message);
}

export async function startRecovery(
  api: ApisauceInstance,
  email: string,
  password: string
): Promise<any> {
  await key.generateE2EKeys(email, password);
  //recovery technically only needs an e2e key but we're generating a recovery key to
  //separate the recovery action from communciation encryption functionality
  //it also protects against strange edge cases like accidentally sending the recovery code
  //to the wrong guardian
  await key.generateRecoveryKey(email, password);
  const response = await api.get<IUser>(`/v1/users/${email}`);
  if (!response.ok || !response.data) {
    const errorData = response.data as { message?: string } | undefined;
    const message = errorData?.message || response.problem || "Unknown error";
    throw new Error(message);
  }
  const user = response.data;
  const encryptedClientPublicKey = storage.loadKey({
    identifier: email,
    type: "e2e.public",
  });
  const clientPublicKey = await key.decryptKey({
    encryptedKeyObject: encryptedClientPublicKey,
    password,
  });
  const keyBundle = await key.generateKeyBundle({
    user,
    password,
    type: "recovery",
  });
  const recoverResponse = await api.post("/v1/users/recovery", {
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

  return { user, clientPublicKey, keyBundle };
}

export async function confirmRecovery(
  api: ApisauceInstance,
  email: string,
  password: string,
  recoveryCode: string
): Promise<any> {
  //decrypt the recovery code
  const decryptedRecoveryBundle = await key.decryptContents({
    encryptedContent: recoveryCode,
    email,
    password,
  });

  //load local recovery key from file and compare to code provided by guardian
  const recoveryBundle = JSON.parse(decryptedRecoveryBundle);
  const { guardian_node_id, recovery_key, recovery_challenge } = recoveryBundle;
  const encryptedLocalRecoveryKey = await storage.loadKey({
    identifier: email,
    type: "recovery",
  });
  const localRecoveryKey = await key.decryptKey({
    encryptedKeyObject: encryptedLocalRecoveryKey,
    password,
  });
  const nodeSpecificKey = key.deriveNodeSpecificKey(
    Buffer.from(localRecoveryKey, "base64"),
    guardian_node_id,
    "recovery"
  );
  if (recovery_key !== nodeSpecificKey) {
    throw new Error("Recovery keys do not match");
  }

  const guardian = await storage.loadGuardian({ nodeId: guardian_node_id });
  const e2ePublicKey = guardian.e2ePublicKey;
  const encryptedRecoveryChallenge = await key.encryptContents({
    content: recovery_challenge,
    publicKey: e2ePublicKey,
    email,
    password,
  });
  const encryptedClientPublicKey = storage.loadKey({
    identifier: email,
    type: "e2e.public",
  });
  const clientPublicKey = await key.decryptKey({
    encryptedKeyObject: encryptedClientPublicKey,
    password,
  });
  console.log("recovery_challenge", recovery_challenge);
  console.log("encryptedRecoveryChallenge", encryptedRecoveryChallenge);
  const response = await api.post("/v1/users/recovery/confirm", {
    email,
    clientPublicKey,
    recoveryCode: encryptedRecoveryChallenge,
  });

  if (!response.ok || !response.data) {
    const errorData = response.data as { message?: string } | undefined;
    const message = errorData?.message || response.problem || "Unknown error";
    throw new Error(message);
  }

  return response.data;
}
