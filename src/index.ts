// index.ts
import { createApiInstance, GridlockApi } from "./api.js";
import { UserService } from "./user/user.service.js";
import { GuardianService } from "./guardian/guardian.service.js";
import { WalletService } from "./wallet/wallet.service.js";
import { AuthService } from "./auth/index.js";
import { IRegisterResponse } from "./user/user.interfaces.js";
import { IAddGuardianParams } from "./guardian/guardian.interfaces.js";

export const ETHEREUM = "ethereum";
export const SOLANA = "solana";
export const SUPPORTED_COINS = [ETHEREUM, SOLANA];

interface IGridlockSdkProps {
  apiKey: string;
  baseUrl: string;
  verbose: boolean;
  logger: any;
}

class GridlockSdk {
  private apiKey: string;
  private baseUrl: string;
  private logger: any;
  api: GridlockApi;
  authService: AuthService;
  userService: UserService;
  guardianService: GuardianService;
  walletService: WalletService;

  constructor(props: IGridlockSdkProps) {
    this.apiKey = props.apiKey;
    this.baseUrl = props.baseUrl;
    this.logger = props.logger || console;

    this.api = createApiInstance(this.baseUrl, this.logger, props.verbose);

    this.authService = new AuthService(this.api, this.logger, props.verbose);
    this.userService = new UserService(this.api, this.logger, props.verbose);
    this.walletService = new WalletService(
      this.api,
      this.authService,
      this.logger,
      props.verbose
    );
    this.guardianService = new GuardianService(
      this.api,
      this.authService,
      this.logger,
      props.verbose
    );
  }

  setVerbose(verbose: boolean) {
    this.api.setVerbose(verbose);
  }

  refreshRequestHandler(token: string) {
    this.api.refreshRequestHandler(token);
  }

  async createUser({
    name,
    email,
    password,
  }: {
    name: string;
    email: string;
    password: string;
  }): Promise<IRegisterResponse> {
    try {
      return await this.userService.createUser({ name, email, password });
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }

  async addGuardian({
    email,
    password,
    guardian,
    isOwnerGuardian,
  }: IAddGuardianParams): Promise<any> {
    try {
      return await this.guardianService.addGuardian({
        email,
        password,
        guardian,
        isOwnerGuardian,
      });
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }

  async createWallet(email: string, password: string, blockchain: string) {
    try {
      return await this.walletService.createWallet(email, password, blockchain);
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
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
    try {
      return await this.walletService.signTransaction({
        email,
        password,
        address,
        message,
      });
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
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
    try {
      return await this.walletService.verifySignature({
        email,
        password,
        message,
        address,
        blockchain,
        signature,
      });
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }

  async getGridlockGuardians() {
    try {
      const response = await this.api.get("/sdk/guardian/gridlock");
      if (response.ok && response.data) {
        return response.data;
      }
      return undefined;
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }
}

export default GridlockSdk;
