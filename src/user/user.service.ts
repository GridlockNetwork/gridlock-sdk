import { ApisauceInstance } from "apisauce";
import * as storage from "../storage/storage.service.js";
import * as key from "../key/key.service.js";
import { IRegisterResponse, IUser } from "./user.interfaces.js";
import { IGuardian } from "../guardian/guardian.interfaces.js";
import { IWallet } from "../wallet/wallet.interfaces.js";

interface IRecoveryResponse {
  guardians: IGuardian[];
}

export async function createUser(
  api: ApisauceInstance,
  name: string,
  email: string,
  password: string,
  saveCredentials: boolean = false
): Promise<IRegisterResponse> {
  const { identityPublicKey } = await key.generateIdentityKeys(email, password);

  const { e2ePublicKey } = await key.generateE2EKeys(email, password);

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
  // Back up existing identity keys before starting recovery
  await key.backupIdentityKeys(email);

  // Generate new identity keys that will be used for the recovered account
  const { identityPublicKey } = await key.generateIdentityKeys(email, password);

  // Generate E2E keys as before
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

  const publicKeyObj = storage.loadKey({
    identifier: email,
    type: "e2e.public",
  });
  const clientE2ePublicKey = publicKeyObj.key;

  const response = await api.get<IUser>(`/v1/users/${email}`);
  if (!response.ok || !response.data) {
    const errorData = response.data as { message?: string } | undefined;
    const message = errorData?.message || response.problem || "Unknown error";
    throw new Error(message);
  }
  const user = response.data;

  const keyBundle = await key.generateKeyBundle({
    password,
    type: "recovery",
    user,
  });

  const recoverResponse = await api.post<IRecoveryResponse>(
    "/v1/users/recovery",
    {
      email,
      clientE2ePublicKey,
      keyBundle,
    }
  );

  if (!recoverResponse.ok) {
    const errorData = recoverResponse.data as { message?: string } | undefined;
    const message =
      errorData?.message || recoverResponse.problem || "Unknown error";
    throw new Error(message);
  }

  // Save each guardian from the response array
  if (
    recoverResponse.data?.guardians &&
    Array.isArray(recoverResponse.data.guardians)
  ) {
    for (const guardian of recoverResponse.data.guardians) {
      await storage.saveGuardian({ guardian });
    }
  }

  return recoverResponse.data;
}

export async function confirmRecovery(
  api: ApisauceInstance,
  email: string,
  password: string,
  recoveryBundle: string
): Promise<{ user: IUser; wallets: IWallet[] }> {
  // Try to decrypt with each guardian's public key
  const guardians = storage.loadGuardians();
  let decryptedRecoveryBundle = null;

  if (guardians.length === 0) {
    throw new Error("No guardians available for decryption.");
  }

  for (const guardian of guardians) {
    try {
      decryptedRecoveryBundle = await key.decryptContents({
        encryptedContent: recoveryBundle,
        senderPublicKey: guardian.e2ePublicKey,
        email,
        password,
      });
      if (decryptedRecoveryBundle) break;
    } catch (error) {
      // Continue to next guardian if decryption fails
      continue;
    }
  }

  if (!decryptedRecoveryBundle) {
    throw new Error(
      "Failed to decrypt recovery email with any guardian's public key"
    );
  }

  //load local recovery key from file and compare to code provided by guardian
  const { guardian_node_id, recovery_key, recovery_challenge } = JSON.parse(
    decryptedRecoveryBundle
  );

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

  // Convert recovery key to signing key now that recovery is confirmed
  await key.convertRecoveryKeyToSigningKey(email, password);

  // Load the already generated identity public key instead of generating new one
  const identityPublicKeyObj = storage.loadKey({
    identifier: email,
    type: "identity.public",
  });
  const identityPublicKey = identityPublicKeyObj.key;

  const publicKeyObj = storage.loadKey({
    identifier: email,
    type: "e2e.public",
  });

  const clientE2ePublicKey = publicKeyObj.key;

  // variable names are written in Rust style since this is meant for the guardian
  const recoveryConfirmation = {
    recovery_challenge: recovery_challenge,
    client_identity_public_key: identityPublicKey,
  };

  const encryptedRecoveryConfirmation = await key.encryptContents({
    content: JSON.stringify(recoveryConfirmation),
    publicKey: guardianE2ePublicKey,
    email,
    password,
  });

  // Generate key bundle for recovery confirmation
  const keyBundle = await key.generateKeyBundle({
    password,
    type: "signing", //recently converted to signing key
    user: { email },
  });

  const response = await api.post<{ user: IUser; wallets: IWallet[] }>(
    "/v1/users/recovery/confirm",
    {
      email,
      clientE2ePublicKey,
      encryptedRecoveryConfirmation: encryptedRecoveryConfirmation,
      keyBundle,
    }
  );

  if (!response.ok || !response.data) {
    const errorData = response.data as { message?: string } | undefined;
    const message = errorData?.message || response.problem || "Unknown error";
    throw new Error(message);
  }

  // Save the updated user and wallet information
  const { user, wallets } = response.data;
  storage.saveUser({ user });
  for (const wallet of wallets) {
    storage.saveWallet({ wallet });
  }

  return response.data;
}

export async function transferOwner(
  api: ApisauceInstance,
  email: string,
  password: string
): Promise<any> {
  // Load user from storage
  const user = await storage.loadUser({ email });
  if (!user) {
    throw new Error("User not found in storage");
  }

  // Load the E2E public key from storage
  const e2ePublicKeyObj = storage.loadKey({
    identifier: email,
    type: "e2e.public",
  });
  const clientE2ePublicKey = e2ePublicKeyObj.key;

  // Load the identity public key from storage
  const identityPublicKeyObj = storage.loadKey({
    identifier: email,
    type: "identity.public",
  });
  const clientIdentityPublicKey = identityPublicKeyObj.key;

  // Generate key bundle for transfer
  const keyBundle = await key.generateKeyBundle({
    user,
    password,
    type: "signing",
  });

  const response = await api.post("/v1/users/transfer", {
    email,
    clientE2ePublicKey,
    clientIdentityPublicKey,
    keyBundle,
  });

  if (!response.ok) {
    const errorData = response.data as { message?: string } | undefined;
    const message = errorData?.message || response.problem || "Unknown error";
    throw new Error(message);
  }

  return response.data;
}
