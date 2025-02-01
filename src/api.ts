// api.ts
import { create, ApisauceInstance } from "apisauce";
import chalk from "chalk";
import moment from "moment";

export interface GridlockApi extends ApisauceInstance {
  setVerbose: (verbose: boolean) => void;
  log: (...args: any[]) => void;
  logError: (error: any) => void;
  refreshRequestHandler: (token: string) => void;
}

export function createApiInstance(
  baseURL: string,
  logger: any,
  verbose: boolean,
  token?: string
): GridlockApi {
  const headers: Record<string, string> = {};
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const api = create({
    baseURL,
    headers,
    withCredentials: true,
    timeout: 60000,
  });

  // Request interceptor with logging
  api.axiosInstance.interceptors.request.use((request) => {
    if (verbose && logger) {
      logger.log(
        `<- ${moment().format("HH:mm:ss")}: ${request.method?.toUpperCase()}: ${
          request.url
        }`
      );
    }
    return request;
  });

  // Response interceptor with logging
  api.axiosInstance.interceptors.response.use(
    (response) => {
      if (verbose && logger) {
        logger.log(
          `-> ${moment().format(
            "HH:mm:ss"
          )}: ${response.config.method?.toUpperCase()}: ${
            response.config.url
          } -- ${response.status}`
        );
      }
      return response;
    },
    async (error) => {
      if (verbose && logger) {
        logger.error(
          `ERROR -> ${moment().format(
            "HH:mm:ss"
          )}: ${error.config?.method?.toUpperCase()}: ${error.config?.url} -- ${
            error?.response?.status
          }`
        );
      }
      return Promise.reject(error);
    }
  );

  // Attach additional methods to the API instance.
  const gridlockApi = api as GridlockApi;

  gridlockApi.setVerbose = (newVerbose: boolean) => {
    // update the verbose flag used by the interceptors and logging functions
    verbose = newVerbose;
  };

  gridlockApi.log = (...args: any[]) => {
    if (!logger || !verbose) return;
    logger.log("\n");
    logger.log(...args);
  };

  gridlockApi.logError = (error: any) => {
    logger.log("");
    if (logger) {
      logger.error(chalk.red.bold(error.message));
      if (verbose) {
        logger.error(chalk.gray(error.stack));
      }
    }
  };

  gridlockApi.refreshRequestHandler = (newToken: string) => {
    if (newToken) {
      api.setHeader("Authorization", `Bearer ${newToken}`);
    } else {
      api.setHeader("Authorization", "");
    }
  };

  return gridlockApi;
}
