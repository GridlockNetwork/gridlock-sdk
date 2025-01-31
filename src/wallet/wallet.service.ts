import { ApisauceInstance } from "apisauce";
import AuthService from "../auth/auth.service.js";
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
    }

    return response;
  }

  async sign(signTransactionData: any) {
    const response = await this.api.post<any>(
      "/v1/wallets/sign",
      signTransactionData
    );
    return response;
  }

  async verifySignature(
    coinType: string,
    message: string,
    signature: string,
    expectedAddress: string
  ) {
    if (!SUPPORTED_COINS.includes(coinType)) {
      return { success: false, error: { message: "Invalid coin type" } };
    }

    try {
      if (coinType === ETHEREUM) {
        const messageHash = hashMessage(message);
        const recoveredAddress = recoverAddress(messageHash, signature);
        const isValid =
          recoveredAddress?.toLowerCase() === expectedAddress?.toLowerCase();
        return { success: true, data: isValid };
      }

      if (coinType === SOLANA) {
        const messageBytes = decodeUTF8(message);
        const signatureBytes = bs58.decode(signature);
        const addressBytes = bs58.decode(expectedAddress);
        const isVerified = nacl.sign.detached.verify(
          messageBytes,
          signatureBytes,
          addressBytes
        );
        return { success: true, data: isVerified };
      }
    } catch (error) {
      return {
        success: false,
        error: { message: "Error trying to check signature" },
      };
    }

    return { success: false, error: { message: "Unsupported coin type" } };
  }

  private async loginWithToken(token: string) {
    // Implement the loginWithToken method here
  }
}

export { WalletService };
