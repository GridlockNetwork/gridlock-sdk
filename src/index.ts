import * as api from "./api.js";
import * as key from "./key/key.service.js";
import * as user from "./user/user.service.js";
import * as guardian from "./guardian/guardian.service.js";
import * as wallet from "./wallet/wallet.service.js";
import AuthService from "./auth/auth.service.js";

import { IRegisterResponse } from "./user/user.interfaces.js";
import {
  IAddGuardianParams,
  IGuardian,
} from "./guardian/guardian.interfaces.js";

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
  }: {
    name: string;
    email: string;
    password: string;
  }): Promise<IRegisterResponse> {
    try {
      return await user.createUser(this.api, name, email, password);
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

  async createWallet(email: string, password: string, blockchain: string) {
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
      return await wallet.verifySignature(
        this.api,
        this.authService,
        email,
        password,
        message,
        address,
        blockchain,
        signature
      );
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }

  async addGridlockGuardian({
    email,
    password,
  }: {
    email: string;
    password: string;
  }): Promise<IGuardian | null> {
    try {
      return await guardian.addGridlockGuardian(
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

  async login(email: string, password: string): Promise<any> {
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
    identifier,
    password,
  }: {
    content: string;
    publicKey: string;
    identifier: string;
    password: string;
  }): Promise<string> {
    try {
      return await key.encryptContents({
        content,
        publicKey,
        identifier,
        password,
      });
    } catch (error) {
      this.api.logError(error);
      throw error;
    }
  }

  async recover({
    email,
    password,
  }: {
    email: string;
    password: string;
  }): Promise<any> {
    try {
      return await user.recover(this.api, email, password);
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
}

export default GridlockSdk;
