import { storage } from "../storage/index.js";
import AuthService, { validateEmailAndPassword } from "../auth/auth.service.js";
import type { IGuardian } from "./guardian.interfaces.js";
import { ApisauceInstance } from "apisauce";

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
  if (user?.ownerGuardian && isOwnerGuardian) {
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
    return response.data;
  } else {
    const errorData = response.data as { message?: string } | undefined;
    const message = errorData?.message || response.problem || "Unknown error";
    throw new Error(message);
  }
}

export async function addGridlockGuardian(
  api: ApisauceInstance,
  authService: AuthService,
  email: string,
  password: string
): Promise<IGuardian | null> {
  await validateEmailAndPassword({ email, password });

  const user = storage.loadUser({ email });

  await authService.login({ email, password });

  const response = await api.post<any>("/v1/users/addGuardian/gridlock", {
    email,
  });
  if (response.ok && response.data) {
    const { user, guardian } = response.data;
    storage.saveUser({ user });
    storage.saveGuardian({ guardian });
    return guardian;
  } else {
    const errorData = response.data as { message?: string } | undefined;
    const message = errorData?.message || response.problem || "Unknown error";
    throw new Error(message);
  }
}
