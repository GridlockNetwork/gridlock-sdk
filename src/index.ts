import { ApisauceInstance, create } from "apisauce";
import { UserService } from "./user/user.service.js";
import { GuardianService } from "./guardian/guardian.service.js";
import { WalletService } from "./wallet/wallet.service.js";
import { AuthService } from "./auth/index.js";
import { v4 as uuidv4 } from "uuid";
import chalk from "chalk";
import {
  IUser,
  ICreateUserData,
  IRegisterResponse,
} from "./user/user.interfaces.js";
import moment from "moment";
import {
  IReplaceGuardianResponse,
  IUserStatusResponse,
  IGuardian,
} from "./guardian/guardian.interfaces.js";
import { IWallet } from "./wallet/wallet.interfaces.js";
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
  private debug: boolean;

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
    this.debug = props.verbose;

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

  private log = (...args: any[]) => {
    if (!this.logger || !this.verbose) return;

    this.logger.log("\n");
    this.logger.log(...args);
  };

  private logError = (error: any) => {
    this.logger.log("");
    if (this.logger) {
      this.logger.error(chalk.red.bold(error.message)); // Make error message stand out
      if (this.verbose) {
        this.logger.error(chalk.gray(error.stack)); // Dim stack trace for readability
      }
    }
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
            const refreshResponse = await this.authService.loginWithToken({
              token,
            });

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
    this.accessToken = token;
    this.api = create({
      baseURL: this.baseUrl,
      headers: {
        Authorization: `Bearer ${token || "undefined"}`,
      },
    });
    this.addInterceptors();
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
      this.logError(error);
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
      this.logError(error);
      throw error;
    }
  }

  async createWallet(email: string, password: string, blockchain: string) {
    try {
      return await this.walletService.createWallet(email, password, blockchain);
    } catch (error) {
      this.logError(error);
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
      const xxx = await this.walletService.signTransaction({
        email,
        password,
        address,
        message,
      });
      return xxx;
    } catch (error) {
      this.logError(error);
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
      this.logError(error);
      throw error;
    }
  }

  async getGridlockGuardians(): Promise<IGuardian | undefined> {
    try {
      const response = await this.api.get<IGuardian>("/sdk/guardian/gridlock");
      if (response.ok && response.data) {
        return response.data;
      }
      return undefined;
    } catch (error) {
      this.logError(error);
      throw error;
    }
  }
}

export default GridlockSdk;
