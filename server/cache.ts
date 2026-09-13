/** A bounded byte cache, shared across listeners. CORS is applied only after cache lookup. */
export class ResponseCache {
  private entries = new Map<string, { body: Uint8Array; headers: [string,string][]; expires: number }>();
  private generation = 0;
  constructor(private readonly maxEntries = 256, private readonly maxBodyBytes = 1_000_000, private readonly maxBytes = 32_000_000) {}
  get epoch() { return this.generation; }
  clear() { this.generation++; this.entries.clear(); }
  async match(request: Request): Promise<Response | undefined> {
    const item = this.entries.get(request.url);
    if (!item) return;
    if (item.expires <= Date.now()) { this.entries.delete(request.url); return; }
    return new Response(item.body.slice(), { headers: item.headers });
  }
  async put(request: Request, response: Response, generation = this.generation) {
    if (response.status !== 200) return;
    const body = new Uint8Array(await response.arrayBuffer());
    if (generation !== this.generation || body.length > this.maxBodyBytes) return;
    const control = response.headers.get('cache-control') ?? '';
    const ttl = Number(control.match(/s-maxage=(\d+)/)?.[1] ?? control.match(/max-age=(\d+)/)?.[1] ?? 60);
    const headers = [...response.headers].filter(([key]) => !key.startsWith('access-control-'));
    this.entries.delete(request.url);
    while (this.entries.size && (this.entries.size >= this.maxEntries || [...this.entries.values()].reduce((sum,item) => sum+item.body.length,body.length)>this.maxBytes)) this.entries.delete(this.entries.keys().next().value!);
    this.entries.set(request.url,{body,headers,expires:Date.now()+ttl*1000});
  }
}
