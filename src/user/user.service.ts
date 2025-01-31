import { ApisauceInstance } from "apisauce";
import { storage } from "../storage/index.js";
import { key } from "../key/index.js";
import { IRegisterData, IRegisterResponse } from "./user.interfaces.js";

export class UserService {
  private api: ApisauceInstance;
  private logger: any;
  private verbose: boolean;

  constructor(api: ApisauceInstance, logger: any, verbose: boolean) {
    this.api = api;
    this.logger = logger;
    this.verbose = verbose;
  }

  async createUser(
    registerData: IRegisterData,
    password: string
  ): Promise<IRegisterResponse> {
    const response = await this.api.post<IRegisterResponse>(
      "/v1/auth/register",
      registerData
    );
    if (response.ok && response.data) {
      const { user, authTokens } = response.data;
      storage.saveTokens({ authTokens, email: user.email });
      storage.saveUser({ user });
      await key.generateUserKeys(user.email, password);
      return response.data;
    }
    this.logger.log("Failed to create user.");
    if (this.verbose) {
      ///this is not working need to figure out verbose
      this.logger.log("Response details:", response);
    }
    throw new Error("Failed to create user");
  }
}
