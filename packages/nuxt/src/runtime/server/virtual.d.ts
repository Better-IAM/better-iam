// Compile-time stand-ins for Nitro's virtual modules. In an app, Nitro resolves them and the module's type template types
// `#better-iam/instance` from the user's file.
declare module '#better-iam/instance' {
  const instance: unknown;
  export const iam: unknown;
  export default instance;
}

declare module '#imports' {
  type Event = { context: Record<string, unknown> };
  export function defineNitroPlugin(
    plugin: (nitroApp: {
      hooks: { hook(name: 'request', handler: (event: Event) => void): void };
    }) => void,
  ): unknown;
  export function defineEventHandler<T>(handler: (event: Event) => T): (event: Event) => T;
  export function toWebRequest(event: Event): Request;
  export function createError(input: {
    statusCode: number;
    statusMessage: string;
    message: string;
    data: { code: string };
  }): Error;
  export function useRuntimeConfig(): Record<string, unknown>;
}
