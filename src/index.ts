import { ApisauceInstance, create } from "apisauce";
import { UserService } from "./user/user.service.js";
import { GuardianService } from "./guardian/guardian.service.js";
import { WalletService } from "./wallet/wallet.service.js";
import { AuthService } from "./auth/index.js";
import { v4 as uuidv4 } from "uuid";
import crypto from "crypto";
import { hashMessage, recoverAddress } from "ethers";
import {
  IUser,
  IRegisterData,
  IRegisterResponse,
} from "./user/user.interfaces.js";
import { AccessAndRefreshTokens } from "./auth/auth.interfaces.js";
import moment from "moment";
import {
  IReplaceGuardianResponse,
  IUserStatusResponse,
  IGuardian,
} from "./guardian/guardian.interfaces.js";
import { IWallet, ICreateWalletParams } from "./wallet/wallet.interfaces.js";
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
  private verbose: boolean;
  private logger: any;
  private accessToken: string = "";
  private retriedRequest: boolean = false; // flag to track if a request has been retried

  api: ApisauceInstance;

  authService: AuthService;
  userService: UserService;
  guardianService: GuardianService;
  walletService: WalletService;

  constructor(props: IGridlockSdkProps) {
    this.apiKey = props.apiKey;
    this.baseUrl = props.baseUrl;
    this.verbose = props.verbose;
    this.logger = props.logger || console;

    this.api = create({
      baseURL: this.baseUrl,
      headers: {
        Authorization: "Bearer undefined",
      },
      withCredentials: true,
      timeout: 60000,
    });

    this.authService = new AuthService(this.api, props.logger, props.verbose);

    this.userService = new UserService(this.api, this.logger, this.verbose);
    this.walletService = new WalletService(
      this.api,
      this.authService,
      this.logger,
      this.verbose
    );
    this.guardianService = new GuardianService(
      this.api,
      this.authService,
      props.logger,
      props.verbose
    );

    this.addInterceptors();
  }

  setVerbose(verbose: boolean) {
    this.verbose = verbose;
  }

  private generateNodeId() {
    return uuidv4();
  }

  private log = (...args: any[]) => {
    if (!this.logger || !this.verbose) return;

    this.logger.log("\n");
    this.logger.log(...args);
  };

  private addInterceptors = () => {
    this.api.axiosInstance.interceptors.request.use((request) => {
      this.log(
        `<- ${moment().format("HH:mm:ss")}: ${request.method?.toUpperCase()}: ${
          request.url
        } `
      );
      return request;
    });

    this.api.axiosInstance.interceptors.response.use(
      (response) => {
        this.log(
          `-> :${moment().format(
            "HH:mm:ss"
          )}: ${response.config.method?.toUpperCase()}: ${
            response.config.url
          } -- ${response.status}`
        );
        return response;
      },
      async (error) => {
        this.log(
          `ERROR-> ${moment().format(
            "HH:mm:ss"
          )}: ${error.config.method?.toUpperCase()}: ${error.config.url} -- ${
            error?.response?.status
          }`
        );
        if (error?.response?.status === 401) {
          if (!this.retriedRequest) {
            this.log("Token expired, trying to refresh it");
            const token = this.accessToken;
            const refreshResponse = await this.authService.loginWithToken(
              token
            );

            if (refreshResponse) {
              // retry the original request with the new token
              error.config.headers[
                "Authorization"
              ] = `Bearer ${this.accessToken}`;
              this.retriedRequest = true;
              return this.api.axiosInstance.request(error.config);
            }
          }
        }
        this.retriedRequest = false;
        return Promise.reject(error);
      }
    );
  };

  refreshRequestHandler(token: string) {
    // console.log('Old Auth Token:', this.accessToken); //debug //this doesn't persist across cli commands. It's always undefined. i think it's because the sdk is reinitialized every time
    // console.log('New Token:', token); //debug
    this.accessToken = token;
    this.api = create({
      baseURL: this.baseUrl,
      headers: {
        Authorization: `Bearer ${token || "undefined"}`,
      },
    });
    this.addInterceptors();
  }

  async createWallet(email: string, password: string, blockchain: string) {
    return this.walletService.createWallet(email, password, blockchain);
  }

  async sign(signTransactionData: any) {
    return this.walletService.sign(signTransactionData);
  }

  async verifySignature(
    coinType: string,
    message: string,
    signature: string,
    expectedAddress: string
  ) {
    return this.walletService.verifySignature(
      coinType,
      message,
      signature,
      expectedAddress
    );
  }

  async getNodes() {
    const response = await this.api.post<IUserStatusResponse>(
      "monitoring/userStatusV2"
    );
    return response;
  }

  async getUser() {
    const response = await this.api.get<IUser>("/user");
    return response;
  }

  async getWallets() {
    const response = await this.api.get<IWallet[]>("/wallet");
    return response;
  }

  async deleteUser() {
    const response = await this.api.delete<any>("/user/safe");
    return response;
  }

  async addUserGuardian(data: { name: string }) {
    const response = await this.api.post<
      Omit<IReplaceGuardianResponse, "state">
    >("user/guardian/add", data);
    return response;
  }

  async addGuardian({
    email,
    password,
    guardian,
    isOwnerGuardian,
  }: IAddGuardianParams): Promise<any> {
    return this.guardianService.addGuardian({
      email,
      password,
      guardian,
      isOwnerGuardian,
    });
  }

  async getGridlockGuardians(): Promise<IGuardian | undefined> {
    const response = await this.api.get<IGuardian>("/sdk/guardian/gridlock");
    if (response.ok && response.data) {
      return response.data;
    }
    return undefined;
  }

  async createUser(
    registerData: IRegisterData,
    password: string
  ): Promise<IRegisterResponse> {
    return this.userService.createUser(registerData, password);
  }
}

export default GridlockSdk;
