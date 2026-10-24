/**
 * WeChat JSSDK Signature API
 * Deploy on Vercel as a serverless function.
 *
 * Env vars needed (set in Vercel dashboard):
 *   WX_APP_ID     - 公众号 AppID
 *   WX_APP_SECRET - 公众号 AppSecret
 */

const crypto = require("crypto");

// In-memory cache (per serverless instance, best-effort)
let cache = {
  accessToken: { value: null, expires: 0 },
  jsapiTicket: { value: null, expires: 0 },
};

async function getAccessToken(appId, appSecret) {
  const now = Date.now();
  if (cache.accessToken.value && now < cache.accessToken.expires) {
    return cache.accessToken.value;
  }

  const url = `https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=${appId}&secret=${appSecret}`;
  const res = await fetch(url);
  const data = await res.json();

  if (data.errcode) {
    throw new Error(`获取 access_token 失败: ${data.errcode} ${data.errmsg}`);
  }

  cache.accessToken = {
    value: data.access_token,
    expires: now + (data.expires_in - 300) * 1000, // 提前5分钟过期
  };

  return data.access_token;
}

async function getJsapiTicket(accessToken) {
  const now = Date.now();
  if (cache.jsapiTicket.value && now < cache.jsapiTicket.expires) {
    return cache.jsapiTicket.value;
  }

  const url = `https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=jsapi&access_token=${accessToken}`;
  const res = await fetch(url);
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

function generateSignature(ticket, nonceStr, timestamp, url) {
  const string1 = `jsapi_ticket=${ticket}&noncestr=${nonceStr}&timestamp=${timestamp}&url=${url}`;
  return crypto.createHash("sha1").update(string1).digest("hex");
}

module.exports = async (req, res) => {
  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const appId = process.env.WX_APP_ID;
  const appSecret = process.env.WX_APP_SECRET;

  if (!appId || !appSecret) {
    return res.status(500).json({
      error: "WX_APP_ID 或 WX_APP_SECRET 未配置",
    });
  }

  // Get URL from query param (frontend must pass the full page URL)
  const url = req.query.url;
  if (!url) {
    return res.status(400).json({
      error: "缺少 url 参数，请传入当前页面的完整 URL",
    });
  }

  try {
    const accessToken = await getAccessToken(appId, appSecret);
    const ticket = await getJsapiTicket(accessToken);
    const nonceStr = crypto.randomBytes(16).toString("hex");
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = generateSignature(ticket, nonceStr, timestamp, url);

    return res.status(200).json({
      appId,
      timestamp,
      nonceStr,
      signature,
    });
  } catch (err) {
    return res.status(500).json({
      error: err.message,
    });
  }
};
