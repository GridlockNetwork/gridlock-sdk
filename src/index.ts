import * as api from "./api.js";
import * as key from "./key/key.service.js";
import * as user from "./user/user.service.js";
import * as guardian from "./guardian/guardian.service.js";
import * as wallet from "./wallet/wallet.service.js";
import AuthService from "./auth/auth.service.js";

import { IRegisterResponse, IUser } from "./user/user.interfaces.js";
import {
  IAddGuardianParams,
  IAddGuardianResponse,
} from "./guardian/guardian.interfaces.js";
import * as storage from "./storage/storage.service.js";

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
  private verbose: boolean;
  private logger: any;
  api: api.GridlockApi;
  authService: AuthService;

  constructor(props: IGridlockSdkProps) {
    this.apiKey = props.apiKey;
    this.baseUrl = props.baseUrl;
    this.verbose = props.verbose;
    this.logger = props.logger || console;

    this.api = api.createApiInstance(this.baseUrl, this.logger, this.verbose);

    this.authService = new AuthService(this.api, this.logger, this.verbose);
  }

  setVerbose(verbose: boolean) {
    this.verbose = verbose;
    this.api.setVerbose(verbose);
    this.authService.verbose = verbose;
  }

  refreshRequestHandler(token: string) {
    this.api.refreshRequestHandler(token);
  }

  async createUser({
    name,
    email,
    password,
    saveCredentials = false,
  }: {
    name: string;
    email: string;
    password: string;
    saveCredentials?: boolean;
  }): Promise<IRegisterResponse> {
    try {
      return await user.createUser(
        this.api,
        name,
        email,
        password,
        saveCredentials
      );
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }

  async addGuardian({
    email,
    password,
    guardian: g,
    isOwnerGuardian,
  }: IAddGuardianParams): Promise<any> {
    try {
      return await guardian.addGuardian(
        this.api,
        this.authService,
        email,
        password,
        g,
        isOwnerGuardian
      );
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }

  async createWallet({
    email,
    password,
    blockchain,
  }: {
    email: string;
    password: string;
    blockchain: string;
  }) {
    try {
      return await wallet.createWallet(
        this.api,
        this.authService,
        email,
        password,
        blockchain
      );
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
      return await wallet.signTransaction(
        this.api,
        this.authService,
        email,
        password,
        address,
        message
      );
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
    signature,
  }: {
    email: string;
    password: string;
    message: string;
    address: string;
    signature: string;
  }) {
    try {
      return await wallet.verifySignature(
        this.api,
        this.authService,
        email,
        password,
        message,
        address,
        signature
      );
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }

  async addProfessionalGuardian({
    email,
    password,
    type,
  }: {
    email: string;
    password: string;
    type: "gridlock" | "partner";
  }): Promise<IAddGuardianResponse> {
    try {
      return await guardian.addProfessionalGuardian(
        this.api,
        this.authService,
        email,
        password,
        type
      );
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }

  async login({
    email,
    password,
  }: {
    email: string;
    password: string;
  }): Promise<any> {
    try {
      return await this.authService.login({ email, password });
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }

  async encryptContents({
    content,
    publicKey,
    email,
    password,
  }: {
    content: string;
    publicKey: string;
    email: string;
    password: string;
  }): Promise<string> {
    try {
      return await key.encryptContents({
        content,
        publicKey,
        email,
        password,
      });
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }

  async startRecovery({
    email,
    password,
  }: {
    email: string;
    password: string;
  }): Promise<any> {
    try {
      return await user.startRecovery(this.api, email, password);
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }

  async addSocialGuardian({
    email,
    password,
  }: {
    email: string;
    password: string;
  }): Promise<void> {
    try {
      await guardian.addSocialGuardian(
        this.api,
        this.authService,
        email,
        password
      );
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }

  hasStoredCredentials(): boolean {
    try {
      return storage.hasStoredCredentials();
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }

  loadStoredCredentials(): {
    email: string;
    password: string;
    timestamp: string;
  } | null {
    try {
      return storage.loadStoredCredentials();
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }

  async saveStoredCredentials({
    email,
    password,
  }: {
    email: string;
    password: string;
  }): Promise<void> {
    try {
      return await storage.saveStoredCredentials({ email, password });
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }

  clearStoredCredentials(): void {
    try {
      storage.clearStoredCredentials();
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }

  async confirmRecovery({
    email,
    password,
    recoveryCode,
  }: {
    email: string;
    password: string;
    recoveryCode: string;
  }): Promise<any> {
    try {
      return await user.confirmRecovery(
        this.api,
        email,
        password,
        recoveryCode
      );
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }
}

export default GridlockSdk;

// Auth module exports
export * as auth from "./auth/index.js";

// Guardian module exports
export * as guardian from "./guardian/index.js";

// User module exports
export * as user from "./user/index.js";

// Wallet module exports
export * as wallet from "./wallet/index.js";

// Storage module exports
export * as storage from "./storage/index.js";
