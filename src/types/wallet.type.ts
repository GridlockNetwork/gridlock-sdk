import { IGuardian } from "./guardian.type";

export interface IWallet {
  userId: string;
  keyId: string;
  name: string;
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
