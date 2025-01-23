import { IGuardian } from "./Guardians";

export interface ICoinWallet {
  _id: string;
  active: boolean;
  network: string;
  created: string;
  associatedGuardians: IGuardian[];
  transactions?: ITransaction[];
  userId: string;
  address: string;
  keyId: string;
  balance: string;
  balanceAsDecimal: number;
  coinType: "ethereum" | "solana";
  type?: string;
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

export interface IGiftCoinWallet extends ICoinWallet {
  code?: string;
}

export interface ICreateMultipleWalletResponse {
  message: string;
  solanaAddress?: string;
  status: string;
  walletList: ICoinWallet[];
  errors: string[];
  carrierWallet?: IGiftCoinWallet;
}
