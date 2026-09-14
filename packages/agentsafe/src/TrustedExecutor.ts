import type { AddressInfo } from "node:net";
import type { ExecutorConfig } from "./config/ExecutorConfig.js";
import { forwardRequestHandlers } from "./handlers/ForwardRequestHandler.js";
import type { HandlerRegistration } from "./handlers/HandlerRegistration.js";
import { ExecutorHttpServer } from "./http/ExecutorHttpServer.js";
import {
  TrustedExecutorService,
  type ServiceDependencies,
} from "./service/TrustedExecutorService.js";

export type TrustedExecutorDependencies = ServiceDependencies;

export interface TrustedExecutorOptions {
  /** `ExecutorConfigLoader.load(env)`, or a configuration built by trusted startup code. */
  readonly config: ExecutorConfig;
  /** The seam: what this process can run. Defaults to the reference forwarding handler. */
  readonly handlers?: HandlerRegistration;
  readonly dependencies?: TrustedExecutorDependencies;
}

export interface TrustedExecutor {
  readonly service: TrustedExecutorService;
  /** Binds the listener; the configured port and address unless overridden. */
  listen(port?: number, address?: string): Promise<AddressInfo>;
  close(): Promise<void>;
}

/**
 * The trusted executor, assembled: the service behind its one listener,
 * with the adopter's handlers registered and the registry sealed. Nothing
 * listens until `listen()` is called, and nothing here reads the process
 * environment; that is `serve()`.
 */
export async function createTrustedExecutor(
  options: TrustedExecutorOptions,
): Promise<TrustedExecutor> {
  const service = TrustedExecutorService.create(
    options.config,
    options.handlers ?? forwardRequestHandlers(),
    options.dependencies ?? {},
  );
  const server = new ExecutorHttpServer(service, options.config.callerToken);
  return {
    service,
    listen: (port = options.config.port, address = options.config.bindAddress) =>
      server.listen(port, address),
    close: () => server.close(),
  };
}
