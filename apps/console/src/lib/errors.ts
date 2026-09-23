/** Better IAM errors are recognised structurally: the library is loaded at runtime, outside the bundle, so `instanceof` cannot be used. */
export interface IamLikeError extends Error {
  code: string;
  status: number;
}

export function isIamError(error: unknown): error is IamLikeError {
  return (
    error instanceof Error &&
    error.name === 'IamError' &&
    typeof (error as { code?: unknown }).code === 'string' &&
    typeof (error as { status?: unknown }).status === 'number'
  );
}

export class ConsoleError extends Error implements IamLikeError {
  constructor(
    readonly code: string,
    message: string,
    readonly status = 400,
  ) {
    super(message);
    this.name = 'IamError';
  }
}
