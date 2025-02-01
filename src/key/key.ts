import crypto from "crypto";
import nacl from "tweetnacl";
import type { IUser } from "../user/user.interfaces.js";
import type {
  INodePassword,
  IPasswordBundle,
} from "../wallet/wallet.interfaces.js";
import { storage } from "../storage/index.js";

export async function generatePasswordBundle({
  user,
  password,
}: {
  user: IUser;
  password: string;
}): Promise<IPasswordBundle> {
  const signingKey = await storage.loadKey({
    identifier: user.email,
    type: "signing",
  });

  const decryptedSigningKey = await decryptKey({
    encryptedKeyObject: signingKey,
    password,
  });

  const nodes: INodePassword[] = [];
  const nodePool = user.nodePool;

  for (const n of nodePool) {
    const nodeSigningKey = getNodeSigningKey(
      Buffer.from(decryptedSigningKey, "base64"),
      n.nodeId
    );
    const encryptedContent = await encryptContents({
      content: nodeSigningKey,
      publicKey: n.publicKey,
      identifier: user.email,
      password,
    });
    nodes.push({ nodeId: n.nodeId, encryptedSigningKey: encryptedContent });
  }

  return { nodes };
}

export async function encryptKey({
  key,
  password,
}: {
  key: string;
  password: string;
}) {
  const salt = crypto.randomBytes(16);
  const derivedKey = await deriveKey(password, salt);
  const stretchedKey = crypto.createHash("sha256").update(derivedKey).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", stretchedKey, iv);
  const encryptedKey = Buffer.concat([
    cipher.update(key, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return {
    key: encryptedKey.toString("base64"),
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    salt: salt.toString("base64"),
    algorithm: "aes-256-gcm",
    createdAt: new Date().toISOString(),
  };
}

export async function decryptKey({
  encryptedKeyObject,
  password,
}: {
  encryptedKeyObject: any;
  password: string;
}) {
  try {
    const { key, iv, authTag, salt } = encryptedKeyObject;
    const derivedKey = await deriveKey(password, Buffer.from(salt, "base64"));
    const stretchedKey = crypto
      .createHash("sha256")
      .update(derivedKey)
      .digest();
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      stretchedKey,
      Buffer.from(iv, "base64")
    );
    decipher.setAuthTag(Buffer.from(authTag, "base64"));
    let decryptedKey = decipher.update(key, "base64", "utf8");
    decryptedKey += decipher.final("utf8");
    return decryptedKey;
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Error decrypting key: ${error.message}`);
    } else {
      throw new Error("An unknown error occurred");
    }
  }
}

function getNodeSigningKey(signingKey: Buffer, nodeId: string): string {
  return Buffer.from(
    crypto.hkdfSync(
      "sha256",
      signingKey,
      Buffer.from(nodeId),
      Buffer.from("node-auth"),
      32
    )
  ).toString("base64");
}

async function encryptContents({
  content,
  publicKey,
  identifier,
  password,
}: {
  content: string;
  publicKey: string;
  identifier: string;
  password: string;
}): Promise<string> {
  const encryptedPrivateKey = storage.loadKey({ identifier, type: "private" });
  const privateKey = await decryptKey({
    encryptedKeyObject: encryptedPrivateKey,
    password,
  });
  const keyPair = nacl.box.keyPair.fromSecretKey(
    Buffer.from(privateKey, "base64")
  );
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const messageUint8 = new TextEncoder().encode(content);
  const publicKeyUint8 = Buffer.from(publicKey, "base64");
  const encryptedMessage = nacl.box(
    messageUint8,
    nonce,
    publicKeyUint8,
    keyPair.secretKey
  );

  return Buffer.concat([nonce, Buffer.from(encryptedMessage)]).toString(
    "base64"
  );
}

async function deriveKey(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(
      password,
      salt,
      32,
      { N: 16384, r: 8, p: 1 },
      (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey);
      }
    );
  });
}

export function generateE2EKey(): { publicKey: string; privateKey: string } {
  const keyPair = nacl.box.keyPair();
  const publicKey = Buffer.from(keyPair.publicKey).toString("base64");
  const privateKey = Buffer.from(keyPair.secretKey).toString("base64");
  return { publicKey, privateKey };
}

export async function generateUserKeys(email: string, password: string) {
  const { publicKey, privateKey } = generateE2EKey();
  const encryptedPublicKey = await encryptKey({ key: publicKey, password });
  const encryptedPrivateKey = await encryptKey({ key: privateKey, password });

  storage.saveKey({
    identifier: email,
    key: encryptedPublicKey,
    type: "public",
  });
  storage.saveKey({
    identifier: email,
    key: encryptedPrivateKey,
    type: "private",
  });

  const signingKey = await generateSigningKey();
  const encryptedSigningKey = await encryptKey({ key: signingKey, password });

  storage.saveKey({
    identifier: email,
    key: encryptedSigningKey,
    type: "signing",
  });
}

export async function generateSigningKey(): Promise<string> {
  return crypto.randomBytes(32).toString("base64");
}
