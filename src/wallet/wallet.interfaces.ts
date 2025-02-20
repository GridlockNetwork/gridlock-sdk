import { IGuardian } from "../guardian/guardian.interfaces.js";
import { IUser } from "../user/user.interfaces.js";

export interface IWallet {
  userId: string;
  keyId: string;
  network: "main" | "ropsten" | "rinkeby";
  address: string;
  pubKey: string;
  blockchain: "ethereum" | "solana";
  associatedGuardians: IGuardian[];
}

interface IBaseTransaction {
  fromAddress: string;
  toAddress: string;
  hash: string;
  nonce?: string;
  blockNumber: string;
  sent: boolean;
  created: Date | string;
}

interface ITransaction extends IBaseTransaction {
  _id?: string;
  timestamp?: number;
  value: string | number;
  transactionHash?: string;
  returnValues?: {
    to: string;
    from: string;
    value: string;
  };
  postBalance: number;
  preBalance: number;
}

export interface IGiftCoinWallet extends IWallet {
  code?: string;
}

export interface ICreateMultipleWalletResponse {
  message: string;
  solanaAddress?: string;
  status: string;
  walletList: IWallet[];
  errors: string[];
  carrierWallet?: IGiftCoinWallet;
}

export interface INodePassword {
  nodeId: string;
  encryptedKey: string;
  encryptedRecoveryEmail: string;
}

export interface IKeyBundle {
  nodes: INodePassword[];
}
export interface ICreateWalletParams {
  blockchain: string;
  user: IUser;
  keyBundle: IKeyBundle;
}
