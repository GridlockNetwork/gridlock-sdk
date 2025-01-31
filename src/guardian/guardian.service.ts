import { storage } from "../storage/index.js";
import AuthService from "../auth/auth.service.js";
import type { IGuardian } from "./guardian.interfaces.js";
import { ApisauceInstance } from "apisauce";

export class GuardianService {
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

  async addGuardian({
    email,
    password,
    guardian,
    isOwnerGuardian,
  }: {
    email: string;
    password: string;
    guardian: IGuardian;
    isOwnerGuardian: boolean;
  }) {
    const authTokens = await this.authService.login({ email, password });
    if (!authTokens) {
      return;
    }
    const response = await this.api.post<any>("/v1/users/addGuardian", {
      guardian,
      isOwnerGuardian,
    });
    if (response.ok && response.data) {
      storage.saveUser({ user: response.data });
      storage.saveGuardian({ guardian });
    }

    return response;
  }
}

// export async function getGridlockGuardians(): Promise<IGuardian[] | null> {
//   const spinner = ora("Retrieving Gridlock guardians...").start();
//   const response = await gridlock.getGridlockGuardians();
//   if (!response.success) {
//     spinner.fail("Failed to retrieve Gridlock guardians");
//     console.error(
//       `Error: ${response.error.message} (Code: ${response.error.code})`
//     );
//     return null;
//   }
//   const guardians = Array.isArray(response.data)
//     ? (response.data as IGuardian[])
//     : [];
//   spinner.succeed("Gridlock guardians retrieved successfully");
//   return guardians;
// }

// export async function addGridlockGuardian() {
//   const spinner = ora("Retrieving Gridlock guardian...").start();
//   const gridlockGuardians = await getGridlockGuardians();
//   if (!gridlockGuardians) {
//     spinner.fail("Failed to retrieve Gridlock guardians");
//     return;
//   }

//   const existingGuardians = storage.loadGuardians();
//   const existingGuardianIds = existingGuardians.map((g) => g.nodeId);

//   const newGuardian = Array.isArray(gridlockGuardians)
//     ? gridlockGuardians.find((g) => !existingGuardianIds.includes(g.nodeId))
//     : null;
//   if (!newGuardian) {
//     spinner.fail("No new Gridlock guardian available to add");
//     return;
//   }

//   storage.saveGuardian({ guardian: newGuardian });
//   spinner.succeed("Gridlock guardian retrieved and saved successfully");
//   await showAvailableGuardians();
// }
