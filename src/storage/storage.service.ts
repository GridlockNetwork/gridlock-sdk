import fs from "fs";
import crypto from "crypto";
import path from "path";
import os from "os";
import type { IUser } from "../user/user.interfaces.js";
import type { IGuardian } from "../guardian/guardian.interfaces.js";
import type { AccessAndRefreshTokens } from "../auth/auth.interfaces.js";
import { validateEmailAndPassword } from "../auth/auth.service.js";

const GUARDIANS_DIR = path.join(os.homedir(), ".gridlock-cli", "guardians");
const USERS_DIR = path.join(os.homedir(), ".gridlock-cli", "users");
const TOKENS_DIR = path.join(os.homedir(), ".gridlock-cli", "tokens");
const KEYS_DIR = path.join(os.homedir(), ".gridlock-cli", "keys");
const WALLETS_DIR = path.join(os.homedir(), ".gridlock-cli", "wallets");
const CREDENTIALS_DIR = path.join(os.homedir(), ".gridlock-cli", "credentials");

function saveData<T>({
  dir,
  filename,
  data,
}: {
  dir: string;
  filename: string;
  data: T;
}) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const filePath = path.join(dir, filename);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n");
}

function loadData<T>({ dir, filename }: { dir: string; filename: string }): T {
  const filePath = path.join(dir, filename);
  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }
  return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}

export function loadToken({
  email,
  type,
}: {
  email: string;
  type: keyof AccessAndRefreshTokens;
}) {
  const authTokens = loadData<AccessAndRefreshTokens>({
    dir: TOKENS_DIR,
    filename: `${email}.token.json`,
  });
  return authTokens ? authTokens[type]?.token || null : null;
}

export function saveTokens({
  authTokens,
  email,
}: {
  authTokens: AccessAndRefreshTokens;
  email: string;
}) {
  saveData({
    dir: TOKENS_DIR,
    filename: `${email}.token.json`,
    data: authTokens,
  });
}

export function saveKey({
  identifier,
  key,
  type,
}: {
  identifier: string;
  key: any;
  type: string;
}) {
  const checksum = crypto
    .createHash("sha256")
    .update(JSON.stringify(key))
    .digest("hex");
  saveData({
    dir: KEYS_DIR,
    filename: `${identifier}.${type}.key.json`,
    data: { ...key, checksum },
  });
}

export function loadKey({
  identifier,
  type,
}: {
  identifier: string;
  type: string;
}) {
  const keyObject = loadData<any>({
    dir: KEYS_DIR,
    filename: `${identifier}.${type}.key.json`,
  });
  const { checksum, ...keyData } = keyObject;
  const calculatedChecksum = crypto
    .createHash("sha256")
    .update(JSON.stringify(keyData))
    .digest("hex");
  if (checksum !== calculatedChecksum) {
    throw new Error(
      "Key file integrity check failed. The file may be corrupted or tampered with."
    );
  }
  return keyData;
}

export function saveGuardian({ guardian }: { guardian: IGuardian }) {
  saveData({
    dir: GUARDIANS_DIR,
    filename: `${guardian.nodeId}.guardian.json`,
    data: guardian,
  });
}

export function loadGuardians(): IGuardian[] {
  if (!fs.existsSync(GUARDIANS_DIR)) {
    return [];
  }
  return fs
    .readdirSync(GUARDIANS_DIR)
    .map((file) => loadData<IGuardian>({ dir: GUARDIANS_DIR, filename: file }))
    .filter((guardian): guardian is IGuardian => guardian !== null);
}

export function loadGuardian({ nodeId }: { nodeId: string }): IGuardian {
  return loadData<IGuardian>({
    dir: GUARDIANS_DIR,
    filename: `${nodeId}.guardian.json`,
  });
}

export function saveUser({ user }: { user: IUser }) {
  saveData({ dir: USERS_DIR, filename: `${user.email}.user.json`, data: user });
}

export function loadUser({ email }: { email: string }): IUser {
  return loadData<IUser>({ dir: USERS_DIR, filename: `${email}.user.json` });
}

export function saveWallet({ wallet }: { wallet: any }) {
  saveData({
    dir: WALLETS_DIR,
    filename: `${wallet.address}.wallet.json`,
    data: wallet,
  });
}

export function loadWallet({ address }: { address: string }) {
  return loadData<any>({
    dir: WALLETS_DIR,
    filename: `${address}.wallet.json`,
  });
}

interface StoredCredentials {
  email: string;
  password: string;
  timestamp: string;
}

export function hasStoredCredentials(): boolean {
  if (!fs.existsSync(CREDENTIALS_DIR)) {
    return false;
  }

  const files = fs.readdirSync(CREDENTIALS_DIR);
  return files.some((file) => file.endsWith(".credentials.json"));
}

export function loadStoredCredentials(): StoredCredentials | null {
  if (!fs.existsSync(CREDENTIALS_DIR)) {
    return null;
  }

  const files = fs.readdirSync(CREDENTIALS_DIR);
  const credentialsFile = files.find((file) =>
    file.endsWith(".credentials.json")
  );

  if (!credentialsFile) {
    return null;
  }

  try {
    return loadData<StoredCredentials>({
      dir: CREDENTIALS_DIR,
      filename: credentialsFile,
    });
  } catch (error) {
    return null;
  }
}

export async function saveStoredCredentials({
  email,
  password,
}: {
  email: string;
  password: string;
}) {
  await validateEmailAndPassword({ email, password });

  if (fs.existsSync(CREDENTIALS_DIR)) {
    const files = fs.readdirSync(CREDENTIALS_DIR);
    files.forEach((file) => {
      if (file.endsWith(".credentials.json")) {
        fs.unlinkSync(path.join(CREDENTIALS_DIR, file));
      }
    });
  }

  const credentials = {
    email,
    password,
    timestamp: new Date().toISOString(),
  };

  saveData<StoredCredentials>({
    dir: CREDENTIALS_DIR,
    filename: `${email}.credentials.json`,
    data: credentials,
  });
}

export function clearStoredCredentials(): void {
  if (fs.existsSync(CREDENTIALS_DIR)) {
    const files = fs.readdirSync(CREDENTIALS_DIR);
    files.forEach((file) => {
      if (file.endsWith(".credentials.json")) {
        fs.unlinkSync(path.join(CREDENTIALS_DIR, file));
      }
    });
  }
}
