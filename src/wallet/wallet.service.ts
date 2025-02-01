import { ApisauceInstance } from "apisauce";
import AuthService, { validateEmailAndPassword } from "../auth/auth.service.js";
import { storage } from "../storage/index.js";
import { generatePasswordBundle } from "../key/key.js";
import { IWallet } from "./wallet.interfaces.js";
import { hashMessage, recoverAddress } from "ethers";
import nacl from "tweetnacl";
import pkg from "tweetnacl-util";
import bs58 from "bs58";

const { decodeUTF8 } = pkg;

const ETHEREUM = "ethereum";
const SOLANA = "solana";
const SUPPORTED_COINS = [ETHEREUM, SOLANA];

class WalletService {
  private api: ApisauceInstance;
  private authService: AuthService;
  private logger: any;
  private verbose: boolean;

  constructor(
    api: ApisauceInstance,
    authService: AuthService,
    logger: any,
    verbose: boolean
  ) {
    this.api = api;
    this.authService = authService;
    this.logger = logger;
    this.verbose = verbose;
  }

  async createWallet(email: string, password: string, blockchain: string) {
    await validateEmailAndPassword({ email, password });

    const user = storage.loadUser({ email });
    if (!user) {
      throw new Error("User not found");
    }

    const authTokens = await this.authService.login({ email, password });

    if (!authTokens) {
      return;
    }

    const passwordBundle = await generatePasswordBundle({ user, password });

    const createWalletData = {
      user,
      blockchain,
      passwordBundle,
    };

    const response = await this.api.post<IWallet>(
      "/v1/wallets",
      createWalletData
    );
    if (response.ok && response.data) {
      storage.saveWallet({ wallet: response.data });
      return response.data;
    }

    const errorData = response.data as { message?: string } | undefined;
    const message = errorData?.message || response.problem || "Unknown error";
    throw new Error(message);
  }

  async signTransaction({
    email,
    password,
    address,
    message,
  }: {
    email: string;
    password: string;
    address: string;
    message: string;
  }) {
    await validateEmailAndPassword({ email, password });

    const user = storage.loadUser({ email });

    const wallet = storage.loadWallet({ address });

    const signTransactionData = {
      user,
      wallet,
      message,
    };

    await this.authService.login({ email, password });

    const response = await this.api.post<any>(
      "/v1/wallets/sign",
      signTransactionData
    );

    if (response.ok && response.data) {
      return response.data;
    }

    const errorData = response.data as { message?: string } | undefined;
    const errorMsg = errorData?.message || response.problem || "Unknown error";
    throw new Error(errorMsg);
  }

  async verifySignature({
    email,
    password,
    message,
    address,
    blockchain,
    signature,
  }: {
    email: string;
    password: string;
    message: string;
    address: string;
    blockchain: string;
    signature: string;
  }) {
    if (!SUPPORTED_COINS.includes(blockchain)) {
      return { success: false, error: { message: "Unsupported blockchain" } };
    }
    await validateEmailAndPassword({ email, password });

    await this.authService.login({ email, password });

    const verifySignatureData = {
      message,
      address,
      blockchain,
      signature,
    };

    const response = await this.api.post<any>(
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
}

export { WalletService };
