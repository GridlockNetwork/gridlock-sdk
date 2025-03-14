import * as storage from "../storage/storage.service.js";
import AuthService, { validateEmailAndPassword } from "../auth/auth.service.js";
import type { IGuardian, IAddGuardianResponse } from "./guardian.interfaces.js";
import { ApisauceInstance } from "apisauce";
import qrcodeTerminal from "qrcode-terminal";

export async function addGuardian(
  api: ApisauceInstance,
  authService: AuthService,
  email: string,
  password: string,
  guardian: IGuardian,
  isOwnerGuardian: boolean
) {
  await validateEmailAndPassword({ email, password });

  const user = storage.loadUser({ email });
  if (user?.ownerGuardianId && isOwnerGuardian) {
    throw new Error("There can only be one owner guardian per user");
  }

  await authService.login({ email, password });

  const response = await api.post<any>("/v1/users/addGuardian/custom", {
    guardian,
    isOwnerGuardian,
  });
  if (response.ok && response.data) {
    storage.saveUser({ user: response.data });
    storage.saveGuardian({ guardian });
    return { user: response.data, guardian };
  } else {
    const errorData = response.data as { message?: string } | undefined;
    const message = errorData?.message || response.problem || "Unknown error";
    throw new Error(message);
  }
}

export async function addProfessionalGuardian(
  api: ApisauceInstance,
  authService: AuthService,
  email: string,
  password: string,
  type: "gridlock" | "partner"
): Promise<IAddGuardianResponse> {
  await validateEmailAndPassword({ email, password });

  const user = storage.loadUser({ email });

  await authService.login({ email, password });

  let response;
  if (type === "partner") {
    response = await api.post<any>("/v1/users/addGuardian/partner", {
      email,
      type,
    });
  } else {
    response = await api.post<any>("/v1/users/addGuardian/gridlock", {
      email,
      type,
    });
  }

  if (response.ok && response.data) {
    const { user, guardian } = response.data;
    storage.saveUser({ user });
    storage.saveGuardian({ guardian });
    return response.data;
  } else {
    const errorData = response.data as { message?: string } | undefined;
    const message = errorData?.message || response.problem || "Unknown error";
    throw new Error(message);
  }
}

export async function addSocialGuardian(
  api: ApisauceInstance,
  authService: AuthService,
  email: string,
  password: string
): Promise<string> {
  await validateEmailAndPassword({ email, password });
  qrcodeTerminal.generate("https://appgridlock.page.link/KSuHdX9R5SSLvFXH7", {
    small: true,
  });
  return "adfads";
}
