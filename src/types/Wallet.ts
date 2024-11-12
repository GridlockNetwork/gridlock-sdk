import { Guardian } from './Guardians';

export interface CoinWallet {
  _id: string;
  active: boolean;
  network: string;
  created: string;
  associatedGuardians: Guardian[];
  transactions?: Transaction[];
  userId: string;
  address: string;
  keyId: string;
  balance: string;
  balanceAsDecimal: number;
  coinType: 'ethereum' | 'solana';
  type?: string;
}

interface BaseTransaction {
  fromAddress: string;
  toAddress: string;
  hash: string;
  nonce?: string;
  blockNumber: string;
  sent: boolean;
  created: Date | string;
}

interface Transaction extends BaseTransaction {
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

export interface GiftCoinWallet extends CoinWallet {
  code?: string;
}

export interface CreateMultipleWalletResponse {
  message: string;
  solanaAddress?: string;
  status: string;
  walletList: CoinWallet[];
  errors: string[];
  carrierWallet?: GiftCoinWallet;
}
