/* ============================================================================
   Capital.com proxy  —  Cloudflare Worker
   ----------------------------------------------------------------------------
   WHY THIS EXISTS
   Capital.com's API is server-side only. A browser can't log in to it directly
   because (a) CORS blocks the request and (b) the login tokens (CST /
   X-SECURITY-TOKEN) come back in response HEADERS that browsers aren't allowed
   to read cross-origin. This Worker does the login server-side, where none of
   that applies, and exposes a clean, CORS-enabled JSON endpoint to your page.

   Your credentials are stored as encrypted Worker SECRETS — never in the HTML
   file, never in the browser, never in a chat. That's the whole point.

   ----------------------------------------------------------------------------
   ONE-TIME SETUP (about 5 minutes, free)

   1. Create a Capital.com API key:
      Settings > API integrations > Generate new key (2FA must be ON first).
      Note the API key and the CUSTOM PASSWORD you set for it.

   2. Install the CLI and log in:
        npm install -g wrangler
        wrangler login

   3. Create the project:
        wrangler init capital-proxy        (choose "Hello World" worker)
      Replace the generated src/index.js with THIS file.

   4. Add your secrets (these prompt you to paste the value; nothing is saved to disk):
        wrangler secret put CAP_API_KEY        # the API key from step 1
        wrangler secret put CAP_IDENTIFIER      # your Capital.com login (email)
        wrangler secret put CAP_PASSWORD        # the API key's custom password
        wrangler secret put ACCESS_TOKEN        # any random string you invent — gates your proxy

      Optional plain vars (set in wrangler.toml under [vars], or as secrets):
        CAP_ENV       = "live"   (default) or "live"
        ALLOW_ORIGIN  = "*"      or your page's exact origin for tighter security

   5. Deploy:
        wrangler deploy
      You'll get a URL like  https://capital-proxy.<you>.workers.dev
      Paste that URL (and your ACCESS_TOKEN) into the terminal's Capital.com fields.

   ----------------------------------------------------------------------------
   USING IT
     Find an epic:   https://<your-worker>/?search=euro&token=YOUR_TOKEN
     Get candles:    https://<your-worker>/?epic=EURUSD&interval=15m&max=500&token=YOUR_TOKEN

   START ON THE live ACCOUNT (CAP_ENV="live"). This proxy only reads prices, but
   the same credentials can place real trades — treat them like a bank password.
   ============================================================================ */

const RES_MAP = {
  "1m": "MINUTE", "5m": "MINUTE_5", "15m": "MINUTE_15",
  "30m": "MINUTE_30", "1h": "HOUR", "4h": "HOUR_4", "1d": "DAY",
};

// Cached session (module scope; survives between requests on a warm worker)
let session = { cst: null, sec: null, at: 0 };

export default {
  async fetch(req, env) {
    const cors = {
      "Access-Control-Allow-Origin": env.ALLOW_ORIGIN || "*",
      "Access-Control-Allow-Methods": "GET,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };
    if (req.method === "OPTIONS") return new Response(null, { headers: cors });

    const url = new URL(req.url);

    // Gate the proxy so strangers can't burn your Capital.com rate limit
    if (env.ACCESS_TOKEN && url.searchParams.get("token") !== env.ACCESS_TOKEN) {
      return json({ error: "Unauthorized — missing or wrong token." }, 401, cors);
    }

    const base = env.CAP_ENV === "live"
      ? "https://api-capital.backend-capital.com"
      : "https://live-api-capital.backend-capital.com";

    try {
      await ensureSession(base, env);

      // --- market search: ?search=euro -> list of epics ---
      const search = url.searchParams.get("search");
      if (search) {
        const r = await capGet(`${base}/api/v1/markets?searchTerm=${encodeURIComponent(search)}`, env, base);
        const j = await r.json();
        const markets = (j.markets || []).map(m => ({
          epic: m.epic, name: m.instrumentName, type: m.instrumentType,
        }));
        return json({ markets }, 200, cors);
      }

      // --- candles: ?epic=EURUSD&interval=15m&max=500 ---
      const epic = url.searchParams.get("epic");
      if (!epic) return json({ error: "Provide ?epic=SYMBOL or ?search=term" }, 400, cors);

      const interval = url.searchParams.get("interval") || "15m";
      const resolution = RES_MAP[interval] || "MINUTE_15";
      const max = Math.min(1000, parseInt(url.searchParams.get("max") || "500", 10) || 500);

      const r = await capGet(
        `${base}/api/v1/prices/${encodeURIComponent(epic)}?resolution=${resolution}&max=${max}`,
        env, base
      );
      const j = await r.json();
      if (!j.prices) {
        return json({ error: j.errorCode || "No prices returned for that epic.", detail: j }, r.status || 502, cors);
      }

      const mid = (o) => {
        if (o == null) return null;
        if (typeof o === "number") return o;
        if (o.bid != null && o.ask != null) return (o.bid + o.ask) / 2;
        return o.bid != null ? o.bid : o.ask;
      };
      const values = j.prices.map(p => ({
        time: Date.parse(p.snapshotTimeUTC || p.snapshotTime) || 0,
        open: mid(p.openPrice), high: mid(p.highPrice),
        low: mid(p.lowPrice), close: mid(p.closePrice),
        volume: p.lastTradedVolume != null ? Number(p.lastTradedVolume) : 0,
      })).filter(v => v.close != null).sort((a, b) => a.time - b.time);

      return json({ epic, resolution, values }, 200, cors);

    } catch (e) {
      return json({ error: String(e && e.message || e) }, 500, cors);
    }
  },
};

function authHeaders(env) {
  return {
    "X-CAP-API-KEY": env.CAP_API_KEY,
    "CST": session.cst,
    "X-SECURITY-TOKEN": session.sec,
    "Content-Type": "application/json",
  };
}

// GET with one automatic re-login if the session expired (401)
async function capGet(target, env, base) {
  let r = await fetch(target, { headers: authHeaders(env) });
  if (r.status === 401) {
    session = { cst: null, sec: null, at: 0 };
    await ensureSession(base, env);
    r = await fetch(target, { headers: authHeaders(env) });
  }
  return r;
}

async function ensureSession(base, env) {
  if (session.cst && session.sec && (Date.now() - session.at) < 9 * 60 * 1000) return;
  if (!env.CAP_API_KEY || !env.CAP_IDENTIFIER || !env.CAP_PASSWORD) {
    throw new Error("Missing secrets: set CAP_API_KEY, CAP_IDENTIFIER, CAP_PASSWORD.");
  }
  const r = await fetch(`${base}/api/v1/session`, {
    method: "POST",
    headers: { "X-CAP-API-KEY": env.CAP_API_KEY, "Content-Type": "application/json" },
    body: JSON.stringify({
      identifier: env.CAP_IDENTIFIER,
      password: env.CAP_PASSWORD,
      encryptedPassword: false,
    }),
  });
  if (!r.ok) {
    const t = await r.text();
    throw new Error(`Capital login failed (${r.status}). Check key/login/password & that CAP_ENV matches the account. ${t.slice(0, 140)}`);
  }
  session = {
    cst: r.headers.get("CST"),
    sec: r.headers.get("X-SECURITY-TOKEN"),
    at: Date.now(),
  };
  if (!session.cst || !session.sec) throw new Error("Login succeeded but tokens were missing from response headers.");
}

function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...cors },
  });
}
