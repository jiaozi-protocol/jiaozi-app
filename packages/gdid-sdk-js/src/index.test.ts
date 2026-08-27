import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Gdid } from "./index.js";

describe("Gdid SDK", () => {
  it("builds client", () => {
    const g = new Gdid({ baseUrl: "http://127.0.0.1:3000", apiKey: "k" });
    assert.ok(g);
  });

  it("verify returns ok:false on resolve failure", async () => {
    const g = new Gdid({
      baseUrl: "http://127.0.0.1:9",
      fetch: async () =>
        new Response(JSON.stringify({ error: "not_found" }), { status: 404 }),
    });
    const v = await g.verify("JP-2099-999999");
    assert.equal(v.ok, false);
  });
});
