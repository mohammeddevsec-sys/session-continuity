export const CHAIN_VERSION = "1.0.0";
export const MAX_DELEGATION_DEPTH = 5;
export const MAX_AUTHORIZATION_ITERATIONS = 1000;
export const MAX_AUTHORIZATION_TIME_MICRO = 1000000;

export const SCOPE = {
  READ:   'operation("read")',
  WRITE:  'operation("write")',
  DELETE: 'operation("delete")',
  ADMIN:  'operation("admin")'
};

export const RESOURCE = {
  PUBLIC:  'resource("public")',
  PRIVATE: 'resource("private")',
  SYSTEM:  'resource("system")'
};
