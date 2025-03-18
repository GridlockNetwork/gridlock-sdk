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
  //
  // Recovery operates through out-of-band email communication, so no additional
  // authentication is strictly necessary. However, we use a dedicated recovery
  // key to distinguish the recovery process from end-to-end encryption. This
  // also mitigates edge cases, such as accidentally sending the recovery code
  // to the wrong guardian.
  // In addition, we can assume the original signing key is lost, so we adopt
  // the recovery key as the new signing key once the recovery is confirmed.
  //
  await key.generateRecoveryKey(email, password);
  const response = await api.get<IUser>(`/v1/users/${email}`);
  if (!response.ok || !response.data) {
    const errorData = response.data as { message?: string } | undefined;
    const message = errorData?.message || response.problem || "Unknown error";
    throw new Error(message);
  }
  const user = response.data;
  const publicKeyObj = storage.loadKey({
    identifier: email,
    type: "e2e.public",
  });
  // Access the key directly from the object since it's no longer encrypted
  const clientPublicKey = publicKeyObj.key;
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
  recoveryEmail: string // Renamed from recoveryCode for clarity
): Promise<any> {
  //decrypt the recovery code
  const decryptedRecoveryBundle = await key.decryptContents({
    encryptedContent: recoveryEmail,
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
    throw new Error(
      "Recovery keys do not match. It is likely that recovery was initiated more than once and you are using the incorrect recovery email."
    );
  }

  const guardian = await storage.loadGuardian({ nodeId: guardian_node_id });
  const guardianE2ePublicKey = guardian.e2ePublicKey;

  // Generally not needed assuming that recovery occurs from a different device
  // Backup existing identity keys before generating new ones
  await key.backupIdentityKeys(email);

  // Convert recovery key to signing key now that recovery is confirmed
  await key.convertRecoveryKeyToSigningKey(email, password);

  // Generate new identity keys
  const { publicKey: newIdentityPublicKey } = await key.generateIdentityKeys(
    email,
    password
  );

  const publicKeyObj = storage.loadKey({
    identifier: email,
    type: "e2e.public",
  });

  const clientE2ePublicKey = publicKeyObj.key;

  // variable names are written in Rust style since this is meant for the guardian
  const recoveryConfirmationBundle = {
    recovery_challenge: recovery_challenge,
    client_identity_public_key: newIdentityPublicKey,
  };

  const encryptedRecoveryConfirmationBundle = await key.encryptContents({
    content: JSON.stringify(recoveryConfirmationBundle),
    publicKey: guardianE2ePublicKey,
    email,
    password,
  });

  const response = await api.post("/v1/users/recovery/confirm", {
    email,
    clientE2ePublicKey,
    recoveryBundle: encryptedRecoveryConfirmationBundle,
  });

  if (!response.ok || !response.data) {
    const errorData = response.data as { message?: string } | undefined;
    const message = errorData?.message || response.problem || "Unknown error";
    throw new Error(message);
  }

  return response.data;
}
