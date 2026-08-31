type ApiErrorBody = { error?: { code?: string; message?: string } };

export class PayoApiClient {
  readonly baseUrl: string;
  readonly accessToken: string;

  constructor(input: { baseUrl: string; accessToken: string }) {
    const url = new URL(input.baseUrl);
    const loopback = new Set(["localhost", "127.0.0.1", "[::1]"]);
    if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback.has(url.hostname))) {
      throw new Error("PAYO_API_URL must use HTTPS unless it targets loopback development.");
    }
    if (url.username || url.password || url.search || url.hash) {
      throw new Error("PAYO_API_URL cannot contain credentials, a query, or a fragment.");
    }
    this.baseUrl = url.href.replace(/\/$/, "");
    this.accessToken = input.accessToken;
  }

  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);
    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        ...init,
        signal: controller.signal,
        headers: {
          accept: "application/json",
          authorization: `Bearer ${this.accessToken}`,
          ...(init.body ? { "content-type": "application/json" } : {}),
          ...init.headers,
        },
      });
      const body = await response.json().catch(() => ({})) as ApiErrorBody & T;
      if (!response.ok) {
        throw new Error(`${body.error?.code ?? "PAYO_API_ERROR"}: ${body.error?.message ?? "Request failed."}`);
      }
      return body;
    } finally {
      clearTimeout(timeout);
    }
  }
}
