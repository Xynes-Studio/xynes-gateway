export interface RequestAuth {
  userId?: string;
  email?: string;
  name?: string;
}

declare global {
  interface Request {
    auth?: RequestAuth;
  }
}

export {};
