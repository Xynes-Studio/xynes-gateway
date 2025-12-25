export interface RequestAuth {
  userId?: string;
  email?: string;
  name?: string;
  avatarUrl?: string;
}

declare global {
  interface Request {
    auth?: RequestAuth;
  }
}

export {};
