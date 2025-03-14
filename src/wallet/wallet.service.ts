import { ApisauceInstance } from "apisauce";
import AuthService, { validateEmailAndPassword } from "../auth/auth.service.js";
import * as storage from "../storage/storage.service.js";
import { generateKeyBundle, decryptKey } from "../key/key.service.js";
import { IWallet } from "./wallet.interfaces.js";
import nacl from "tweetnacl";
import pkg from "tweetnacl-util";
import bs58 from "bs58";

const { decodeUTF8 } = pkg;

const ETHEREUM = "ethereum";
const SOLANA = "solana";
const SUPPORTED_COINS = [ETHEREUM, SOLANA];

export async function createWallet(
  api: ApisauceInstance,
  authService: AuthService,
  email: string,
  password: string,
  blockchain: string
) {
  await validateEmailAndPassword({ email, password });

  const user = storage.loadUser({ email });

  if (!user.ownerGuardianId) {
    throw new Error(
      "Complete guardian setup by adding a guardian of type 'Owner Guardian' to create a wallet."
    );
  }
  if (!user.nodePool || user.nodePool.length < 3) {
    throw new Error(
      "You must have at least three guardians in your node pool to create a wallet."
    );
  }

  const encryptedPublicKey = storage.loadKey({
    identifier: email,
    type: "e2e.public",
  });

  const e2ePublicKey = await decryptKey({
    encryptedKeyObject: encryptedPublicKey,
    password,
  });

  const authTokens = await authService.login({ email, password });

  if (!authTokens) {
    return;
  }

  const keyBundle = await generateKeyBundle({
    user,
    password,
    type: "signing",
  });

  const createWalletData = {
    user,
    blockchain,
    clientPublicKey: e2ePublicKey,
    keyBundle,
  };

  const response = await api.post<IWallet>("/v1/wallets", createWalletData);
  if (response.ok && response.data) {
    storage.saveWallet({ wallet: response.data });
    return response.data;
  }
  const errorData = response.data as { message?: string } | undefined;
  const message = errorData?.message || response.problem || "Unknown error";
  throw new Error(message);
}

export async function signTransaction(
  api: ApisauceInstance,
  authService: AuthService,
  email: string,
  password: string,
  address: string,
  message: string
) {
  await validateEmailAndPassword({ email, password });

  const user = storage.loadUser({ email });
  const wallet = storage.loadWallet({ address });

  // Load and decrypt the client public key
  const encryptedPublicKey = storage.loadKey({
    identifier: email,
    type: "e2e.public",
  });
  const e2ePublicKey = await decryptKey({
    encryptedKeyObject: encryptedPublicKey,
    password,
  });

  const keyBundle = await generateKeyBundle({
    user,
    password,
    type: "signing",
  });

  const signTransactionData = {
    user,
    wallet,
    message,
    clientPublicKey: e2ePublicKey,
    keyBundle,
  };

  await authService.login({ email, password });

  const response = await api.post<any>("/v1/wallets/sign", signTransactionData);

  if (response.ok && response.data) {
    return response.data;
  }

  const errorData = response.data as { message?: string } | undefined;
  const errorMsg = errorData?.message || response.problem || "Unknown error";
  throw new Error(errorMsg);
}

export async function verifySignature(
  api: ApisauceInstance,
  authService: AuthService,
  email: string,
  password: string,
  message: string,
  address: string,
  signature: string
) {
  await validateEmailAndPassword({ email, password });

  const wallet = storage.loadWallet({ address });
  if (!wallet) {
    throw new Error(`Wallet with address ${address} not found`);
  }

  await authService.login({ email, password });

  const verifySignatureData = {
    message,
    wallet,
    signature,
  };

  const response = await api.post<any>(
    "/v1/wallets/verify",
    verifySignatureData
  );

  if (response.ok && response.data) {
    return response.data;
  }

  const errorData = response.data as { message?: string } | undefined;
  const errorMsg = errorData?.message || response.problem || "Unknown error";
  throw new Error(errorMsg);
}
