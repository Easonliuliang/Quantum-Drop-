import type { IncomingMessage, ServerResponse } from "http";

declare module "express" {
  export interface Request extends IncomingMessage {
    body?: unknown;
    header(name: string): string | undefined;
  }

  export interface Response extends ServerResponse {
    status(code: number): Response;
    json(body: unknown): Response;
  }

  export type NextFunction = () => void;

  export type RequestHandler = (req: Request, res: Response, next: NextFunction) => void;

  export interface Application {
    use(handler: RequestHandler): Application;
    post(path: string, ...handlers: RequestHandler[]): Application;
    get(path: string, ...handlers: RequestHandler[]): Application;
    listen(port: number, callback?: () => void): void;
  }

  export interface JsonBodyParserOptions {
    limit?: string;
  }

  export interface ExpressFactory {
    (): Application;
    json(options?: JsonBodyParserOptions): RequestHandler;
  }

  const express: ExpressFactory;
  export default express;
}
