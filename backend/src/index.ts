export interface Env {
  APP_ENV?: string;
}

const headers = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") {
      return new Response(JSON.stringify({
        ok: true,
        service: "kch-api",
        environment: env.APP_ENV ?? "development",
        stage: "foundation",
      }), { status: 200, headers });
    }
    return new Response(JSON.stringify({
      error: "not_found",
      message: "Route not found",
    }), { status: 404, headers });
  },
};
