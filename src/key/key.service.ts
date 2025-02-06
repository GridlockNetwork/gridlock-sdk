import crypto from "crypto";
import nacl from "tweetnacl";
import type { IUser } from "../user/user.interfaces.js";
import type { INodePassword, IKeyBundle } from "../wallet/wallet.interfaces.js";
import * as storage from "../storage/storage.service.js";

export async function generateKeyBundle({
  user,
  password,
  type,
}: {
  user: IUser;
  password: string;
  type: string;
}): Promise<IKeyBundle> {
  const rootKey = await storage.loadKey({
    identifier: user.email,
    type: type,
  });

  const decryptedRootKey = await decryptKey({
    encryptedKeyObject: rootKey,
    password,
  });

  const nodes: INodePassword[] = [];
  const nodePool = user.nodePool;

  for (const n of nodePool) {
    const nodeSpecificKey = deriveNodeSpecificKey(
      Buffer.from(decryptedRootKey, "base64"),
      n.nodeId,
      type
    );

    //const fakeNodeSigningKey = nodeSigningKey + "THIS-IS-FAKE-FOR-TESTING";
    const encryptedContent = await encryptContents({
      content: nodeSpecificKey,
      publicKey: n.publicKey,
      identifier: user.email,
      password,
    });
    nodes.push({ nodeId: n.nodeId, encryptedKey: encryptedContent });
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

export function deriveNodeSpecificKey(
  signingKey: Buffer,
  nodeId: string,
  type: string
): string {
  const derivedKey = Buffer.from(
    crypto.hkdfSync(
      "sha256",
      signingKey,
      Buffer.from(nodeId),
      Buffer.from("node-auth"),
      32
    )
  ).toString("base64");
  return `node_${type}_${nodeId}_${derivedKey}`;
}

export async function encryptContents({
  content,
  publicKey,
  identifier,
  password,
}: {
  content: string;
  publicKey: string;
  identifier: string; //usually email
  password: string;
}): Promise<string> {
  const encryptedPrivateKey = storage.loadKey({
    identifier,
    type: "e2e.private",
  });
  const e2ePrivateKey = await decryptKey({
    encryptedKeyObject: encryptedPrivateKey,
    password,
  });
  const keyPair = nacl.box.keyPair.fromSecretKey(
    Buffer.from(e2ePrivateKey, "base64")
  );
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const messageUint8 = new TextEncoder().encode(content);
  const publicKeyUint8 = Buffer.from(publicKey, "base64");
  const publicKeyBytes = new Uint8Array(Buffer.from(publicKey, "base64"));
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

export async function generateE2EKeys(email: string, password: string) {
  const keyPair = nacl.box.keyPair();
  const publicKey = Buffer.from(keyPair.publicKey).toString("base64");
  const privateKey = Buffer.from(keyPair.secretKey).toString("base64");
  const encryptedPublicKey = await encryptKey({ key: publicKey, password });
  const encryptedPrivateKey = await encryptKey({ key: privateKey, password });
  storage.saveKey({
    identifier: email,
    key: encryptedPublicKey,
    type: "e2e.public",
  });
  storage.saveKey({
    identifier: email,
    key: encryptedPrivateKey,
    type: "e2e.private",
  });
  return { publicKey };
}

export async function generateSigningKey(email: string, password: string) {
  const accessKey = "access_" + crypto.randomBytes(32).toString("base64");
  const encryptedKey = await encryptKey({ key: accessKey, password });
  storage.saveKey({
    identifier: email,
    key: encryptedKey,
    type: "signing",
  });
}

export async function generateIdentityKeys(email: string, password: string) {
  const keyPair = nacl.sign.keyPair();
  const publicKey = Buffer.from(keyPair.publicKey).toString("base64");
  const privateKey = Buffer.from(keyPair.secretKey).toString("base64");
  const encryptedPublicKey = await encryptKey({ key: publicKey, password });
  const encryptedPrivateKey = await encryptKey({ key: privateKey, password });
  storage.saveKey({
    identifier: email,
    key: encryptedPublicKey,
    type: "identity.public",
  });
  storage.saveKey({
    identifier: email,
    key: encryptedPrivateKey,
    type: "identity.private",
  });
  return { publicKey };
}

export async function generateRecoveryKey(email: string, password: string) {
  const recoveryKey = "recovery_" + crypto.randomBytes(32).toString("base64");
  const encryptedRecoveryKey = await encryptKey({ key: recoveryKey, password });
  storage.saveKey({
    identifier: email,
    key: encryptedRecoveryKey,
    type: "recovery",
  });
}
