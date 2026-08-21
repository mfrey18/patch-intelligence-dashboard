/** Apply exact-origin CORS for the static read-only dashboard. */
export function addPublicCorsHeaders(headers: Headers, request: Request, configuredOrigins?: string): boolean {
  const origin = request.headers.get("origin");
  if (!origin || !allowedOrigins(configuredOrigins).has(origin)) return false;
  headers.set("access-control-allow-origin", origin);
  headers.append("vary", "Origin");
  return true;
}

export function publicCorsPreflight(request: Request, configuredOrigins?: string): Response {
  const headers = new Headers({ "cache-control": "public, max-age=86400" });
  if (!addPublicCorsHeaders(headers, request, configuredOrigins)) return new Response(null, { status: 403, headers: { "cache-control": "no-store" } });
  headers.set("access-control-allow-methods", "GET, OPTIONS");
  headers.set("access-control-allow-headers", "Accept, Content-Type");
  headers.set("access-control-max-age", "86400");
  return new Response(null, { status: 204, headers });
}

export function allowedOrigins(configuredOrigins?: string): Set<string> {
  return new Set((configuredOrigins ?? "").split(",").map((value) => value.trim()).filter((value) => {
    try {
      const url = new URL(value);
      return (url.protocol === "https:" || url.hostname === "localhost" || url.hostname === "127.0.0.1") && url.origin === value.replace(/\/$/, "") && !url.username && !url.password;
    } catch { return false; }
  }).map((value) => new URL(value).origin));
}
