/**
 * WeChat JSSDK Signature API
 * Compatible with both Vercel (serverless) and Railway (standard Node.js server)
 *
 * Env vars needed:
 *   WX_APP_ID     - 公众号 AppID
 *   WX_APP_SECRET - 公众号 AppSecret
 *   PORT          - 服务端口 (Railway 自动提供)
 */

const crypto = require("crypto");
const http = require("http");
const url = require("url");

// In-memory cache
let cache = {
  accessToken: { value: null, expires: 0 },
  jsapiTicket: { value: null, expires: 0 },
};

async function getAccessToken(appId, appSecret) {
  const now = Date.now();
  if (cache.accessToken.value && now < cache.accessToken.expires) {
    return cache.accessToken.value;
  }

  const apiUrl = `https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=${appId}&secret=${appSecret}`;
  const res = await fetch(apiUrl);
  const data = await res.json();

  if (data.errcode) {
    throw new Error(`获取 access_token 失败: ${data.errcode} ${data.errmsg}`);
  }

  cache.accessToken = {
    value: data.access_token,
    expires: now + (data.expires_in - 300) * 1000,
  };

  return data.access_token;
}

async function getJsapiTicket(accessToken) {
  const now = Date.now();
  if (cache.jsapiTicket.value && now < cache.jsapiTicket.expires) {
    return cache.jsapiTicket.value;
  }

  const apiUrl = `https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=jsapi&access_token=${accessToken}`;
  const res = await fetch(apiUrl);
  const data = await res.json();

  if (data.errcode) {
    throw new Error(`获取 jsapi_ticket 失败: ${data.errcode} ${data.errmsg}`);
  }

  cache.jsapiTicket = {
    value: data.ticket,
    expires: now + (data.expires_in - 300) * 1000,
  };

  return data.ticket;
}

function generateSignature(ticket, nonceStr, timestamp, pageUrl) {
  const string1 = `jsapi_ticket=${ticket}&noncestr=${nonceStr}&timestamp=${timestamp}&url=${pageUrl}`;
  return crypto.createHash("sha1").update(string1).digest("hex");
}

// Request handler (works for both Vercel serverless and standard Node.js)
async function handler(req, res) {
  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(200);
    return res.end();
  }

  const parsedUrl = url.parse(req.url, true);
  const pageUrl = parsedUrl.query.url;

  if (!pageUrl) {
    res.writeHead(400, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "缺少 url 参数" }));
  }

  const appId = process.env.WX_APP_ID;
  const appSecret = process.env.WX_APP_SECRET;

  if (!appId || !appSecret) {
    res.writeHead(500, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "WX_APP_ID 或 WX_APP_SECRET 未配置" }));
  }

  try {
    const accessToken = await getAccessToken(appId, appSecret);
    const ticket = await getJsapiTicket(accessToken);
    const nonceStr = crypto.randomBytes(16).toString("hex");
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = generateSignature(ticket, nonceStr, timestamp, pageUrl);

    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ appId, timestamp, nonceStr, signature }));
  } catch (err) {
    res.writeHead(500, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: err.message }));
  }
}

// Export for Vercel serverless
module.exports = handler;

// If running as standalone (Railway, local, etc.)
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  const server = http.createServer(handler);
  server.listen(PORT, () => {
    console.log(`WeChat JSSDK signature server running on port ${PORT}`);
  });
}
