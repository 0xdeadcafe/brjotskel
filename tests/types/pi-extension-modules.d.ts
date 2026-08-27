declare module "typebox" {
  export const Type: {
    Object(properties?: Record<string, unknown>, options?: Record<string, unknown>): Record<string, unknown>;
    String(options?: Record<string, unknown>): Record<string, unknown>;
    Number(options?: Record<string, unknown>): Record<string, unknown>;
    Boolean(options?: Record<string, unknown>): Record<string, unknown>;
    Array(items: unknown, options?: Record<string, unknown>): Record<string, unknown>;
    Optional(schema: unknown): Record<string, unknown>;
  };
}

declare module "@earendil-works/pi-ai" {
  export function StringEnum<T extends readonly string[]>(values: T, options?: Record<string, unknown>): Record<string, unknown>;
}

declare module "@earendil-works/pi-coding-agent" {
  export const DEFAULT_MAX_BYTES: number;
  export const DEFAULT_MAX_LINES: number;

  export function truncateTail(text: string, options?: { maxBytes?: number; maxLines?: number }): {
    content: string;
    truncated: boolean;
    outputLines: number;
    totalLines: number;
    outputBytes: number;
    totalBytes: number;
  };

  export function formatSize(bytes: number): string;

  export interface CommandContext {
    hasUI?: boolean;
    ui: {
      setStatus(name: string, value: string | undefined): void;
      notify(...args: any[]): void;
      confirm(...args: any[]): Promise<boolean>;
      theme: {
        success(text: string): string;
        warning(text: string): string;
        error(text: string): string;
        muted(text: string): string;
        fg(color: string, text: string): string;
      };
    };
  }

  export interface ExtensionEventMap {
    before_agent_start: { systemPrompt: string };
    session_start: unknown;
    session_shutdown: unknown;
  }

  export interface ToolSpec {
    name: string;
    label?: string;
    description?: string;
    promptSnippet?: string;
    promptGuidelines?: string[];
    parameters?: unknown;
    execute(
      toolCallId: string,
      params: any,
      signal: AbortSignal | undefined,
      onUpdate: ((update: unknown) => void) | undefined,
      ctx: CommandContext,
    ): unknown | Promise<unknown>;
  }

  export interface CommandSpec {
    description?: string;
    getArgumentCompletions?(args: string, ctx: CommandContext): any[] | Promise<any[]>;
    handler(args: string, ctx: CommandContext): unknown | Promise<unknown>;
  }

  export interface ExtensionAPI {
    registerTool(tool: ToolSpec): void;
    registerCommand(name: string, spec: CommandSpec): void;
    on<K extends keyof ExtensionEventMap>(
      event: K,
      handler: (event: ExtensionEventMap[K], ctx: CommandContext) => unknown | Promise<unknown>,
    ): void;
  }
}
