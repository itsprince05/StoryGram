const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = 'https://api.pocketfm.com';
const WORKER_PROXY_URL = 'https://curl-proxy.bruceliu-dev.workers.dev/';
const PHP_BACKEND_URL = process.env.PHP_BACKEND_URL || 'https://princeapps.com/StoryGram';
const PHP_API_KEY = process.env.PHP_API_KEY || 'StoryGramSecretKey_9874981488';

function decryptPocketFmBlob(clientTs, deviceId, cipherBase64) {
  const rawData = `${deviceId}:${clientTs}`;
  const encoded = Buffer.from(rawData).toString('base64');
  const chars = encoded.split('');
  for (let i = 0; i < chars.length - 1; i += 2) {
    const temp = chars[i];
    chars[i] = chars[i + 1];
    chars[i + 1] = temp;
  }
  const keyString = chars.join('');

  const cipherBytes = Buffer.from(cipherBase64, 'base64');
  if (cipherBytes.length < 28) {
    throw new Error('Invalid cipher payload length: ' + cipherBytes.length);
  }

  const salt = cipherBytes.subarray(0, 16);
  const iv = cipherBytes.subarray(16, 28);
  const tag = cipherBytes.subarray(cipherBytes.length - 16);
  const ciphertext = cipherBytes.subarray(28, cipherBytes.length - 16);

  const derivedKey = crypto.pbkdf2Sync(keyString, salt, 10000, 32, 'sha256');
  const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(ciphertext, null, 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

let cachedCookies = '';
let cachedToken = '';
let lastFetchDate = '';
let isRefreshing = false;

const APP_CLIENT_SECRET = 'StoryGramSecClient_98741488';
const APP_HMAC_SECRET = 'StoryGram_Sec_Hmac_98741488_Key_v1';
const rateLimitMap = new Map();
const usedNonces = new Map();
const userStatusCache = new Map();
const USER_CACHE_TTL = 5 * 60 * 1000;

function verifyDynamicSignature(req) {
  const ts = req.headers['x-app-timestamp'];
  const nonce = req.headers['x-app-nonce'];
  const sig = req.headers['x-app-signature'];
  const deviceId = req.headers['x-app-device-id'] || '';
  if (!ts || !nonce || !sig) return false;

  const now = Date.now();
  const reqTime = parseInt(ts, 10);
  if (isNaN(reqTime) || Math.abs(now - reqTime) > 15000) {
    return false;
  }

  if (usedNonces.has(nonce)) {
    return false;
  }
  usedNonces.set(nonce, reqTime + 15000);
  if (usedNonces.size > 10000) {
    for (const [k, exp] of usedNonces.entries()) {
      if (now > exp) usedNonces.delete(k);
    }
  }

  const payloadWithDevice = `${ts}:${nonce}:${req.path}:${deviceId}`;
  const payloadPlain = `${ts}:${nonce}:${req.path}`;
  const expectedSig1 = crypto.createHmac('sha256', APP_HMAC_SECRET).update(payloadWithDevice).digest('hex');
  const expectedSig2 = crypto.createHmac('sha256', APP_HMAC_SECRET).update(payloadPlain).digest('hex');

  const sigBuf = Buffer.from(sig);
  const buf1 = Buffer.from(expectedSig1);
  const buf2 = Buffer.from(expectedSig2);

  if (sigBuf.length === buf1.length && crypto.timingSafeEqual(sigBuf, buf1)) {
    return true;
  }
  if (sigBuf.length === buf2.length && crypto.timingSafeEqual(sigBuf, buf2)) {
    return true;
  }
  return false;
}

function rateLimiterMiddleware(req, res, next) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const now = Date.now();
  const windowMs = 30000;
  const maxRequests = 120;

  const record = rateLimitMap.get(ip) || { count: 0, resetTime: now + windowMs };
  if (now > record.resetTime) {
    record.count = 1;
    record.resetTime = now + windowMs;
  } else {
    record.count++;
  }
  rateLimitMap.set(ip, record);

  if (record.count > maxRequests) {
    return res.status(429).json({ success: false, error: 'Too many requests' });
  }

  if (rateLimitMap.size > 5000) {
    for (const [k, exp] of rateLimitMap.entries()) {
      if (now > exp.resetTime) rateLimitMap.delete(k);
    }
  }
  next();
}

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || origin === 'null' || origin.startsWith('file://') || origin.endsWith('.onrender.com') || origin.includes('localhost') || origin.includes('127.0.0.1')) {
      return callback(null, true);
    }
    return callback(null, false);
  },
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(rateLimiterMiddleware);

app.use((req, res, next) => {
  if (req.path === '/' || req.path === '/index.html') {
    return next();
  }

  const ua = (req.headers['user-agent'] || '').toLowerCase();

  const isScraper = ua.includes('curl') || ua.includes('python') || ua.includes('postman') || ua.includes('insomnia') || ua.includes('scrapy') || ua.includes('aiohttp') || ua.includes('go-http-client');
  if (isScraper && !req.headers['x-app-signature']) {
    return res.status(403).json({ success: false, error: 'Forbidden' });
  }

  if (req.path.startsWith('/api/') || req.path.startsWith('/user/') || req.path.startsWith('/library')) {
    const isSignedApp = verifyDynamicSignature(req);
    if (!isSignedApp) {
      return res.status(403).json({ success: false, error: 'Unauthorized: Invalid or expired dynamic signature' });
    }
  }

  next();
});

async function verifyUserFromHeaders(req) {
  const userId = req.headers['x-user-id'] || '';
  const deviceId = req.headers['x-device-id'] || req.headers['x-app-device-id'] || '';
  if (!userId) return null;

  const cacheKey = `${userId}:${deviceId}`;
  const cached = userStatusCache.get(cacheKey);
  if (cached && (Date.now() - cached.time) < USER_CACHE_TTL) {
    return cached.data;
  }

  try {
    const phpResponse = await axios.post(`${PHP_BACKEND_URL}/verify_user.php`, {
      user_id: userId,
      email: userId.includes('@') ? userId : '',
      device_id: deviceId,
      api_key: PHP_API_KEY,
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || ''
    }, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-KEY': PHP_API_KEY
      },
      timeout: 8000,
      validateStatus: () => true
    });

    if (phpResponse && phpResponse.data) {
      userStatusCache.set(cacheKey, { data: phpResponse.data, time: Date.now() });

      if (userStatusCache.size > 5000) {
        const now = Date.now();
        for (const [k, v] of userStatusCache.entries()) {
          if ((now - v.time) > USER_CACHE_TTL) userStatusCache.delete(k);
        }
      }

      return phpResponse.data;
    }
  } catch (e) { }
  return null;
}

app.use(async (req, res, next) => {
  const needsUserCheck = (
    req.path.startsWith('/api/') || req.path.startsWith('/home') || req.path.startsWith('/feed') ||
    req.path.startsWith('/show') || req.path.startsWith('/search') || req.path.startsWith('/library')
  ) && !req.path.includes('/user/verify') && !req.path.includes('/health') && !req.path.includes('/ping');

  if (!needsUserCheck) return next();

  const userId = req.headers['x-user-id'] || '';
  if (!userId) return next();

  const userData = await verifyUserFromHeaders(req);
  if (userData) {
    const status = (userData.status || '').toLowerCase();
    if (status === 'blocked') {
      return res.status(403).json({ success: false, status: 'blocked', message: 'Account Blocked' });
    }
    if (status === 'expired') {
      return res.status(403).json({ success: false, status: 'expired', message: 'Access Expired' });
    }
    if (userData.device_mismatch === true || status === 'device_mismatch') {
      return res.status(403).json({ success: false, status: 'device_mismatch', message: 'Device Not Matched' });
    }
    req.verifiedUser = userData;
  }
  next();
});

async function fetchDailyCookiesFromWebsite() {
  const targetUrls = [
    'https://pocketfm.com/',
    'https://www.pocketfm.com/'
  ];

  const webHeaders = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9,hi;q=0.8'
  };

  for (const targetUrl of targetUrls) {
    try {
      let rawSetCookie = null;
      let bodyContent = '';

      try {
        const directRes = await axios.get(targetUrl, {
          headers: webHeaders,
          timeout: 10000,
          validateStatus: () => true,
          maxRedirects: 5
        });
        rawSetCookie = directRes.headers['set-cookie'] || directRes.headers['Set-Cookie'];
        bodyContent = typeof directRes.data === 'string' ? directRes.data : JSON.stringify(directRes.data || '');
      } catch (e) { }

      if (!rawSetCookie || (Array.isArray(rawSetCookie) && rawSetCookie.length === 0) || !bodyContent) {
        const proxyPayload = {
          url: targetUrl,
          method: 'GET',
          headers: webHeaders
        };

        const workerResponse = await axios.post(WORKER_PROXY_URL, proxyPayload, {
          headers: {
            'Accept': '*/*',
            'Content-Type': 'application/json',
            'Origin': 'https://curlonline.com',
            'Referer': 'https://curlonline.com/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36'
          },
          timeout: 30000,
          validateStatus: () => true
        });

        const resHeaders = workerResponse.data?.headers || workerResponse.headers || {};
        rawSetCookie = resHeaders['set-cookie'] || resHeaders['Set-Cookie'] || resHeaders['set_cookie'] || '';
        bodyContent = workerResponse.data?.body !== undefined ? workerResponse.data.body : workerResponse.data;
        if (typeof bodyContent !== 'string') {
          bodyContent = JSON.stringify(bodyContent || {});
        }
      }

      let cookieList = [];
      if (Array.isArray(rawSetCookie)) {
        cookieList = rawSetCookie.map(c => c.split(';')[0].trim());
      } else if (typeof rawSetCookie === 'string' && rawSetCookie) {
        cookieList = rawSetCookie.split(/,(?=[^;]+=[^;]+)/).map(c => c.split(';')[0].trim());
      }

      if (cookieList.length > 0) {
        cachedCookies = cookieList.join('; ');
      }

      const jwtMatch = bodyContent.match(/eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}/);
      if (jwtMatch && jwtMatch[0]) {
        cachedToken = jwtMatch[0];
      }

      for (const cookieItem of cookieList) {
        const parts = cookieItem.split('=');
        if (parts.length >= 2) {
          const key = parts[0].trim().toLowerCase();
          const val = parts.slice(1).join('=').trim();
          if (key === 'auth-token' || key === 'auth_token' || key === 'token' || (val.startsWith('eyJ') && val.includes('.'))) {
            cachedToken = val;
          }
        }
      }

      if (cachedToken) {
        break;
      }
    } catch (err) {
      console.error(`Error fetching daily cookies from ${targetUrl}:`, err.message);
    }
  }
}

async function ensureDailySession(force = false) {
  const today = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Kolkata' }).format(new Date());
  if (force || lastFetchDate !== today || !cachedToken) {
    if (!isRefreshing) {
      isRefreshing = true;
      try {
        await fetchDailyCookiesFromWebsite();
        if (cachedToken) {
          lastFetchDate = today;
        }
      } finally {
        isRefreshing = false;
      }
    }
  }
}

app.use(async (req, res, next) => {
  if (req.path === '/health' || req.path === '/ping') {
    return next();
  }
  await ensureDailySession();
  next();
});

function buildPocketHeaders(req) {
  let token = req.headers['authorization'] || req.headers['auth'] || req.headers['x-auth-token'] || cachedToken || process.env.DEFAULT_BEARER_TOKEN || '';

  if (token && !token.toLowerCase().startsWith('bearer ')) {
    token = `Bearer ${token.trim()}`;
  }

  const language = req.headers['language'] || req.headers['selected_language'] || req.query.language || req.query.selected_language || 'hindi';

  const headers = {
    'Host': 'api.pocketfm.com',
    'app-name': 'pocket_fm',
    'platform': 'android',
    'content-type': 'application/json;charset=utf-8',
    'accept': 'application/json',
    'version-name': '9.1.3',
    'platform-version': '29',
    'app-version': '2013',
    'language': language,
    'authorization': token,
    'accept-encoding': 'gzip',
    'User-Agent': 'com.radio.pocketfm'
  };

  if (cachedCookies) {
    headers['Cookie'] = cachedCookies;
  }

  return headers;
}

async function fetchViaWorkerProxy(targetUrl, headers, method = 'GET', body = null) {
  const proxyPayload = {
    url: targetUrl,
    method: method.toUpperCase(),
    headers: headers
  };

  if (['POST', 'PUT', 'PATCH'].includes(method.toUpperCase()) && body && Object.keys(body).length > 0) {
    proxyPayload.body = typeof body === 'string' ? body : JSON.stringify(body);
  }

  const workerResponse = await axios.post(WORKER_PROXY_URL, proxyPayload, {
    headers: {
      'Accept': '*/*',
      'Accept-Language': 'en-US,en;q=0.9,hi;q=0.8',
      'Content-Type': 'application/json',
      'Origin': 'https://curlonline.com',
      'Referer': 'https://curlonline.com/',
      'sec-ch-ua': '"Chromium";v="148", "Microsoft Edge";v="148", "Not/A)Brand";v="99"',
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors',
      'sec-fetch-site': 'cross-site',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0'
    },
    timeout: 30000,
    validateStatus: () => true
  });

  const statusCode = workerResponse.data?.status || workerResponse.status || 200;
  let bodyData = workerResponse.data?.body !== undefined ? workerResponse.data.body : workerResponse.data;

  if (typeof bodyData === 'string') {
    try {
      bodyData = JSON.parse(bodyData);
    } catch (err) { }
  }

  return { statusCode, data: bodyData };
}

async function forwardToPocketFM(targetUrl, req, res) {
  try {
    const headers = buildPocketHeaders(req);

    if (!headers.authorization || headers.authorization === 'Bearer ') {
      return res.status(401).json({
        success: false,
        error: "Missing Authorization token. Please pass 'authorization' or 'auth' in headers."
      });
    }

    const { statusCode, data } = await fetchViaWorkerProxy(targetUrl, headers, req.method, req.body);

    if (typeof data === 'object' && data !== null) {
      return res.status(statusCode).json(data);
    } else {
      return res.status(statusCode).send(data);
    }
  } catch (error) {
    return res.status(error.response?.status || 500).json({
      success: false,
      message: 'Failed to fetch from Pocket FM API via Worker Proxy',
      error: error.message,
      details: error.response?.data || null
    });
  }
}

app.get(['/health', '/ping'], (req, res) => {
  res.status(200).json({
    status: 'online',
    message: 'API Proxy is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    hasDailyCookies: Boolean(cachedCookies),
    hasDailyToken: Boolean(cachedToken),
    cookies: cachedCookies || "No cookies found",
    token: cachedToken || "",
    lastFetchDate: lastFetchDate
  });
});

app.get(['/cookies', '/api/cookies'], async (req, res) => {
  await ensureDailySession();
  res.status(200).json({
    status: 1,
    cookies: cachedCookies || "No cookies found",
    token: cachedToken || "",
    lastFetchDate: lastFetchDate
  });
});

app.get(['/refresh-cookies', '/api/refresh-cookies'], async (req, res) => {
  await ensureDailySession(true);
  res.status(200).json({
    status: 1,
    message: cachedToken ? "Cookies & Token refreshed successfully" : "Attempted refresh, check token status",
    cookies: cachedCookies || "No cookies found",
    token: cachedToken || "",
    lastFetchDate: lastFetchDate
  });
});

app.get(['/home', '/feed', '/api/feed'], async (req, res) => {
  try {
    const headers = buildPocketHeaders(req);

    if (!headers.authorization || headers.authorization === 'Bearer ') {
      return res.status(401).json({
        success: false,
        error: "Missing Authorization token. Please pass 'authorization' or 'auth' in headers.",
        cookies: cachedCookies || "No cookies found",
        token: cachedToken || ""
      });
    }

    const language = req.headers['language'] || req.headers['selected_language'] || req.query.language || req.query.selected_language || 'hindi';
    const apiType = req.headers['api_type'] || req.headers['api-type'] || req.query.api_type || 'explore_v2';

    const queryParams = new URLSearchParams({
      api_type: apiType,
      selected_language: language,
      ...req.query
    }).toString();

    const url = `${BASE_URL}/v2/feed_api/get_feed_data?${queryParams}`;
    const { statusCode, data } = await fetchViaWorkerProxy(url, headers, 'GET');

    if (!data || typeof data !== 'object') {
      return res.status(statusCode).send(data);
    }

    const rawModules = Array.isArray(data.result) ? data.result : [];
    const filteredResult = [];

    for (const mod of rawModules) {
      if (!mod) continue;

      const rawEntities = Array.isArray(mod.entities) ? mod.entities : [];
      const entities = [];

      for (const ent of rawEntities) {
        if (!ent || !ent.value) continue;

        const info = ent.value.show_info || ent.value;
        const showId = ent.value.show_id || info.show_id || info.entity_id || "";
        const showTitle = info.show_title || info.title || "";
        const imageUrl = info.image_url || info.cover_url || info.gift_url || "";
        const categoryRank = info.show_category_rank !== undefined ? info.show_category_rank : (info.rank !== undefined ? info.rank : null);

        const statsObj = info.stats || {};
        const avgRating = statsObj.avg_rating !== undefined ? statsObj.avg_rating : (statsObj.rating !== undefined ? statsObj.rating : null);
        const totalPlaysDisplay = statsObj.total_plays_display || (statsObj.total_plays ? String(statsObj.total_plays) : "");

        if (showTitle || showId) {
          entities.push({
            value: {
              show_title: showTitle,
              image_url: imageUrl,
              show_category_rank: categoryRank,
              show_id: showId,
              stats: {
                avg_rating: avgRating,
                total_plays_display: totalPlaysDisplay
              }
            }
          });
        }
      }

      if (entities.length > 0 || mod.module_name) {
        filteredResult.push({
          module_name: mod.module_name || "",
          entities: entities
        });
      }
    }

    const formattedResponse = {
      status: data.status !== undefined ? data.status : 1,
      message: data.message || "Home feed details",
      result: filteredResult
    };

    return res.status(200).json(formattedResponse);
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Failed to process feed',
      cookies: cachedCookies || "No cookies found",
      token: cachedToken || "",
      error: error.message
    });
  }
});

app.get(['/search', '/api/search'], async (req, res) => {
  try {
    const headers = buildPocketHeaders(req);

    if (!headers.authorization || headers.authorization === 'Bearer ') {
      return res.status(401).json({
        success: false,
        error: "Missing Authorization token. Please pass 'authorization' or 'auth' in headers."
      });
    }

    const query = req.headers['query'] || req.headers['q'] || req.query.query || req.query.q || '';
    const genre = req.headers['genre'] || req.query.genre || '';
    const language = req.headers['language'] || req.headers['selected_language'] || req.query.language || req.query.selected_language || 'hindi';

    const queryParams = new URLSearchParams({
      query: query,
      genre: genre,
      selected_language: language,
      language: language,
      ...req.query
    }).toString();

    const url = `${BASE_URL}/v3/search/universal.search?${queryParams}`;
    const { statusCode, data } = await fetchViaWorkerProxy(url, headers, 'GET');

    if (typeof data === 'object' && data !== null) {
      if (data.result && data.result.shows && Array.isArray(data.result.shows)) {
        const formattedShows = data.result.shows.map(show => {
          const showId = show.show_id || show.entity_id || "";
          return {
            show_id: showId,
            title: show.title || show.show_title || "",
            plays: show.plays !== undefined ? String(show.plays) : "",
            avg_rating: show.avg_rating !== undefined ? show.avg_rating : (show.rating !== undefined ? show.rating : null),
            image_url: show.image_url || show.cover_url || ""
          };
        });

        return res.status(200).json({
          status: data.status !== undefined ? data.status : 1,
          message: data.message || "successfully fetched shows",
          result: {
            shows: formattedShows
          }
        });
      }
      return res.status(statusCode).json(data);
    } else {
      return res.status(statusCode).send(data);
    }
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Failed to process search',
      error: error.message
    });
  }
});

app.get(['/show', '/show/:show_id', '/api/show', '/api/show/:show_id'], async (req, res) => {
  try {
    const showId = req.headers['show_id'] || req.headers['show-id'] || req.headers['showid'] || req.params.show_id || req.query.show_id;

    if (!showId) {
      return res.status(400).json({
        success: false,
        error: "Missing 'show_id'. Pass it in headers (show_id: ...) or query params (?show_id=...)"
      });
    }

    const headers = buildPocketHeaders(req);

    if (!headers.authorization || headers.authorization === 'Bearer ') {
      return res.status(401).json({
        success: false,
        error: "Missing Authorization token. Please pass 'authorization' or 'auth' in headers."
      });
    }

    const startPtr = parseInt(req.headers['curr_ptr'] || req.headers['curr-ptr'] || req.headers['currptr'] || req.query.curr_ptr || '0', 10);
    const pageSource = req.headers['page_source'] || req.headers['page-source'] || req.query.page_source || 'show_detail';
    const batchSize = Math.min(Math.max(parseInt(req.headers['limit'] || req.query.limit || '20', 10), 1), 50);

    const ptrList = [];
    for (let i = 0; i < batchSize; i++) {
      ptrList.push(startPtr + i);
    }

    const fetchPromises = ptrList.map(ptr => {
      const queryParams = new URLSearchParams({
        show_id: showId,
        curr_ptr: String(ptr),
        info_level: String(ptr),
        page_source: pageSource
      }).toString();

      const targetUrl = `${BASE_URL}/v2/content_api/show.get_details?${queryParams}`;
      return fetchViaWorkerProxy(targetUrl, headers, 'GET')
        .then(resObj => ({ ptr, resData: resObj }))
        .catch(err => ({ ptr, error: err }));
    });

    const results = await Promise.all(fetchPromises);
    results.sort((a, b) => a.ptr - b.ptr);

    let baseShow = null;
    const allStories = [];
    const seenStoryIds = new Set();

    for (const item of results) {
      if (!item.resData || !item.resData.data) continue;
      const json = item.resData.data;

      if (!baseShow && json.result && Array.isArray(json.result) && json.result[0]) {
        baseShow = json.result[0];
      }

      if (json.result && Array.isArray(json.result) && json.result[0] && Array.isArray(json.result[0].stories)) {
        for (const story of json.result[0].stories) {
          if (story && story.story_id) {
            if (seenStoryIds.has(story.story_id)) continue;
            seenStoryIds.add(story.story_id);

            let videoInfoObj = story.video_info || story.video_urls || story.video_url_info || story.video_player || story.video || null;
            if (typeof videoInfoObj === 'string') {
              try {
                videoInfoObj = JSON.parse(videoInfoObj);
              } catch (e) {
                videoInfoObj = null;
              }
            }

            const androidVideoUrl = (videoInfoObj && videoInfoObj.android && videoInfoObj.android.video_url) || (story.android && story.android.video_url) || "";
            const webVideoUrl = (videoInfoObj && videoInfoObj.web && videoInfoObj.web.video_url) || (story.web && story.web.video_url) || "";
            const realMediaUrlEnc = story.media_url_enc || story.media_url || "";
            const videoDashUrl = story.video_url || androidVideoUrl || realMediaUrlEnc || "";

            const storyObj = {
              story_title: story.story_title || story.title || "",
              show_id: story.show_id || (baseShow && baseShow.show_id) || showId,
              image_url: story.image_url || story.cover_url || (baseShow && baseShow.image_url) || "",
              duration: typeof story.duration === 'number' ? story.duration : parseFloat(story.duration || '0'),
              story_id: story.story_id || ""
            };

            const finalVideoUrl = webVideoUrl || (story.video_url && !story.video_url.includes('.mpd') && story.video_url.includes('.m3u8') ? story.video_url : "");

            if (finalVideoUrl) {
              storyObj.audio_url = videoDashUrl;
              storyObj.video_url = finalVideoUrl;
            } else if (realMediaUrlEnc) {
              storyObj.media_url_enc = realMediaUrlEnc;
            } else if (story.audio_url) {
              storyObj.audio_url = story.audio_url;
            }

            allStories.push(storyObj);
          }
        }
      }
    }

    if (!baseShow) {
      return res.status(500).json({
        success: false,
        error: 'Failed to fetch show details from Pocket FM'
      });
    }

    const filteredResponse = {
      status: 1,
      message: "Result for show details page",
      result: [
        {
          show_title: baseShow.show_title || baseShow.title || "",
          image_url: baseShow.image_url || baseShow.cover_url || baseShow.gift_url || "",
          show_category_rank: baseShow.show_category_rank !== undefined ? baseShow.show_category_rank : (baseShow.rank !== undefined ? baseShow.rank : null),
          show_id: baseShow.show_id || showId,
          episodes_count: typeof baseShow.episodes_count === 'number' ? baseShow.episodes_count : parseInt(baseShow.episodes_count || '0', 10),
          stories: allStories,
          next_ptr: startPtr + allStories.length,
          stats: {
            avg_rating: baseShow.stats?.avg_rating !== undefined ? baseShow.stats.avg_rating : null,
            total_plays_display: baseShow.stats?.total_plays_display || ""
          }
        }
      ]
    };

    return res.status(200).json(filteredResponse);
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Failed to process show details batch',
      error: error.message
    });
  }
});

app.get(['/api/license', '/api/get_license'], async (req, res) => {
  try {
    const showId = req.headers['show_id'] || req.headers['show-id'] || req.headers['showid'] || req.query.show_id;
    if (!showId) {
      return res.status(400).json({ success: false, error: "Missing 'show_id'. Please pass 'show_id' in headers." });
    }

    const headers = buildPocketHeaders(req);
    headers['platform'] = 'android';
    headers['version-name'] = '9.1.3';
    headers['platform-version'] = '29';
    headers['app-version'] = '2013';
    headers['device-id'] = 'mobile-web';
    headers['device_id'] = 'mobile-web';
    headers['client-ts'] = '1770000000';
    headers['User-Agent'] = 'com.radio.pocketfm';

    const targetUrl = `${BASE_URL}/v2/content_api/show.play_details?show_id=${encodeURIComponent(showId)}`;
    const { statusCode, data } = await fetchViaWorkerProxy(targetUrl, headers, 'GET');

    if (!data || typeof data !== 'object') {
      return res.status(statusCode).json({ success: false, error: 'Invalid response from PocketFM' });
    }

    const blob = data.blob;
    if (!blob) {
      return res.status(400).json({ success: false, error: 'No DRM blob found in response', data });
    }

    const licenseUrl = decryptPocketFmBlob(1770000000, 'mobile-web', blob);
    return res.status(200).json({
      success: true,
      license_url: licenseUrl
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Failed to resolve DRM license',
      error: error.message
    });
  }
});

app.post(['/api/widevine-license', '/widevine-license'], express.raw({ type: '*/*', limit: '10mb' }), async (req, res) => {
  try {
    const targetLicenseUrl = req.query.url || req.headers['license-url'] || req.headers['license_url'];
    if (!targetLicenseUrl) {
      return res.status(400).send("Missing target license URL");
    }

    const licenseRes = await axios.post(targetLicenseUrl, req.body, {
      headers: {
        'Content-Type': req.headers['content-type'] || 'application/octet-stream',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
      },
      responseType: 'arraybuffer',
      timeout: 15000,
      validateStatus: () => true
    });

    res.set({
      'Content-Type': licenseRes.headers['content-type'] || 'application/octet-stream',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': '*'
    });

    return res.status(licenseRes.status).send(licenseRes.data);
  } catch (err) {
    console.error("Widevine proxy license error:", err.message);
    return res.status(500).send(err.message);
  }
});

app.all(['/unlock', '/api/unlock', '/api/subscribe', '/api/user_action'], async (req, res) => {
  try {
    const headers = buildPocketHeaders(req);

    if (!headers.authorization || headers.authorization === 'Bearer ') {
      return res.status(401).json({
        success: false,
        error: "Missing Authorization token. Please pass 'authorization' or 'auth' in headers."
      });
    }

    const showId = req.headers['show_id'] || req.headers['show-id'] || req.headers['entity_id'] || req.headers['entity-id'] || req.query.show_id || req.query.entity_id || req.body?.show_id || req.body?.entity_id;
    const storyId = req.headers['story_id'] || req.headers['story-id'] || req.headers['storyid'] || req.query.story_id || req.body?.story_id;

    if (!showId || !storyId) {
      return res.status(400).json({
        success: false,
        error: "Missing 'show_id' or 'story_id'. Please pass them in headers, query params or body."
      });
    }

    const action = req.headers['action'] || req.query.action || req.body?.action || 'subscribe_story';
    const entityType = req.headers['entity_type'] || req.headers['entity-type'] || req.query.entity_type || req.body?.entity_type || 'show';
    const source = req.headers['source'] || req.query.source || req.body?.source || 'player';

    const payload = {
      action: action,
      entity_id: showId,
      entity_type: entityType,
      progress_action: "",
      source: source,
      story_id: storyId
    };

    const targetUrl = `${BASE_URL}/v2/user_api/user_action.update`;
    const { statusCode, data } = await fetchViaWorkerProxy(targetUrl, headers, 'POST', payload);

    if (typeof data === 'object' && data !== null) {
      return res.status(statusCode).json(data);
    } else {
      return res.status(statusCode).send(data);
    }
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Failed to update user action',
      error: error.message
    });
  }
});

app.get(['/unlocked', '/api/unlocked', '/api/saved_stories', '/api/get_saved_stories'], async (req, res) => {
  try {
    const headers = buildPocketHeaders(req);

    if (!headers.authorization || headers.authorization === 'Bearer ') {
      return res.status(401).json({
        success: false,
        error: "Missing Authorization token. Please pass 'authorization' or 'auth' in headers."
      });
    }

    const showIds = req.headers['show_id'] || req.headers['show-id'] || req.headers['show_ids'] || req.headers['show-ids'] || req.headers['showid'] || req.query.show_id || req.query.show_ids;

    if (!showIds) {
      return res.status(400).json({
        success: false,
        error: "Missing 'show_id' (or 'show_ids'). Please pass it in headers or query params."
      });
    }

    const targetUrl = `${BASE_URL}/v2/feed_api/get_saved_stories?show_ids=${encodeURIComponent(showIds)}`;
    const { statusCode, data } = await fetchViaWorkerProxy(targetUrl, headers, 'GET');

    if (typeof data === 'object' && data !== null) {
      return res.status(statusCode).json(data);
    } else {
      return res.status(statusCode).send(data);
    }
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Failed to process saved stories',
      error: error.message
    });
  }
});




app.post(['/api/user/verify', '/user/verify'], async (req, res) => {
  const isFormatJson = req.query.format === 'json' ||
    req.headers['x-response-format'] === 'json' ||
    (req.body && (req.body.action === 'update_language' || req.body.format === 'json'));

  try {
    const { email, name, photoUrl, photo_url, deviceId, device_id, userId, user_id, google_id, language, lang, action, req_action } = req.body;
    
    if (!email) {
      if (isFormatJson) {
        return res.status(400).json({ success: false, error: 'Email is required' });
      }
      return res.status(400).send('<div style="color:#f87171;padding:20px;text-align:center;">Email is required</div>');
    }

    const payload = {
      user_id: user_id || userId || google_id || '',
      email,
      name: name || 'User',
      photo_url: photoUrl || photo_url || '',
      device_id: deviceId || device_id || '',
      language: language || lang || '',
      action: action || req_action || '',
      api_key: PHP_API_KEY,
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || ''
    };

    let phpResponse = null;
    let lastError = null;

    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        phpResponse = await axios.post(`${PHP_BACKEND_URL}/verify_user.php`, payload, {
          headers: {
            'Content-Type': 'application/json',
            'X-API-KEY': PHP_API_KEY
          },
          timeout: 10000,
          validateStatus: () => true
        });
        if (phpResponse && phpResponse.data) {
          break;
        }
      } catch (err) {
        lastError = err;
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    }

    if (!phpResponse || !phpResponse.data) {
      throw (lastError || new Error('Verification backend unreachable'));
    }

    if (isFormatJson) {
      return res.status(phpResponse.status).json(phpResponse.data);
    }

    if (phpResponse.data && (phpResponse.data.status === 'active' || phpResponse.data.success === true)) {
      return res.sendFile(path.join(__dirname, 'app_full.html'));
    }

    const userPhoto = payload.photo_url || (phpResponse.data && phpResponse.data.user && phpResponse.data.user.photo) || '';
    const userName = (phpResponse.data && phpResponse.data.user && phpResponse.data.user.name) || payload.name || 'User';
    const userEmail = (phpResponse.data && phpResponse.data.user && phpResponse.data.user.email) || payload.email || '';

    const avatarHtml = userPhoto
      ? `<img src="${userPhoto}" alt="Avatar" style="width:100%;height:100%;object-fit:cover;border-radius:50%;">`
      : `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="5"/><path d="M20 21a8 8 0 0 0-16 0"/></svg>`;

    const noAccessHtml = `
<style>
  .account-page-wrap { width: 100%; max-width: 480px; padding: 10px; margin-top: 56px; display: flex; flex-direction: column; gap: 10px; box-sizing: border-box; }
  .account-profile-card { width: 100%; background: linear-gradient(135deg, rgba(255, 51, 102, 0.12) 0%, rgba(15, 23, 42, 0.8) 100%); border: 1px solid rgba(255, 51, 102, 0.25); border-radius: 20px; padding: 10px; display: flex; align-items: center; gap: 10px; box-sizing: border-box; }
  .account-avatar { width: 50px; height: 50px; border-radius: 50%; background: #182238; border: 2px solid rgba(255, 255, 255, 0.1); display: flex; align-items: center; justify-content: center; color: #94a3b8; overflow: hidden; flex-shrink: 0; }
  .account-user-info { min-width: 0; flex: 1; }
  .account-user-name { font-size: 15px; font-weight: 700; color: #ffffff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .account-user-email { font-size: 12px; color: #94a3b8; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 2px; }
  .restricted-status-card { width: 100%; background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 14px; padding: 10px; text-align: center; box-sizing: border-box; }
  .restricted-status-badge { font-size: 16px; font-weight: 800; color: #f87171; margin: 0; }
</style>
<div class="account-page-wrap">
  <div class="account-profile-card">
    <div class="account-avatar">${avatarHtml}</div>
    <div class="account-user-info">
      <div class="account-user-name">${userName}</div>
      <div class="account-user-email">${userEmail}</div>
    </div>
  </div>
  <div class="restricted-status-card">
    <div class="restricted-status-badge">No Access</div>
  </div>
</div>`;

    return res.status(200).send(noAccessHtml);
  } catch (error) {
    if (isFormatJson) {
      return res.status(500).json({
        success: false,
        status: 'server_error',
        message: 'Failed to connect to verification server'
      });
    }
    return res.status(500).send('<div style="color:#f87171;padding:20px;text-align:center;">Failed to connect to verification server</div>');
  }
});

app.post(['/api/app/bundle', '/app/bundle'], async (req, res) => {
  try {
    const { email, deviceId, device_id } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, error: 'Email required' });
    }

    const phpResponse = await axios.post(`${PHP_BACKEND_URL}/verify_user.php`, {
      email,
      device_id: deviceId || device_id || '',
      api_key: PHP_API_KEY
    }, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-KEY': PHP_API_KEY
      },
      timeout: 15000,
      validateStatus: () => true
    });

    if (phpResponse.data && (phpResponse.data.status === 'active' || phpResponse.data.success === true)) {
      return res.sendFile(path.join(__dirname, 'app_full.html'));
    } else {
      return res.status(403).json({ success: false, status: 'restricted', message: 'User is not active' });
    }
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.post(['/api/admin/users', '/admin/users'], async (req, res) => {
  try {
    const phpResponse = await axios.post(`${PHP_BACKEND_URL}/admin.php`, { action: 'list_users' }, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-KEY': PHP_API_KEY
      },
      timeout: 15000,
      validateStatus: () => true
    });
    return res.status(phpResponse.status).json(phpResponse.data);
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.all(['/api/library', '/library'], async (req, res) => {
  try {
    const method = req.method.toLowerCase();
    const config = {
      method: method,
      url: `${PHP_BACKEND_URL}/library.php`,
      headers: {
        'Content-Type': 'application/json',
        'X-API-KEY': PHP_API_KEY
      },
      timeout: 15000,
      validateStatus: () => true
    };
    if (method === 'post' || method === 'put') {
      config.data = req.body;
    } else {
      config.params = req.query;
    }
    const phpResponse = await axios(config);
    return res.status(phpResponse.status).json(phpResponse.data);
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.all('/api/proxy/*', (req, res) => {
  const endpointPath = req.params[0];
  const queryParams = new URLSearchParams(req.query).toString();
  const url = `${BASE_URL}/${endpointPath}${queryParams ? `?${queryParams}` : ''}`;
  return forwardToPocketFM(url, req, res);
});

const NGINX_404_HTML = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>404 Not Found</title><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#fff;color:#222;padding:40px 20px;max-width:600px;margin:0 auto;line-height:1.6;}h1{font-size:24px;font-weight:600;color:#111;margin-bottom:8px;border-bottom:1px solid #eaeaea;padding-bottom:12px;}p{font-size:14px;color:#555;margin-bottom:20px;}hr{border:none;border-top:1px solid #eaeaea;margin:20px 0;}address{font-size:12px;color:#888;font-style:normal;}</style></head><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p><hr><address>nginx / 1.24.0</address></body></html>`;

app.get(['/', '/index.html'], (req, res) => {
  const isSigned = verifyDynamicSignature(req);

  if (!isSigned) {
    return res.status(404).send(NGINX_404_HTML);
  }

  res.sendFile(path.join(__dirname, 'index.html'));
});

app.use((req, res) => {
  res.status(404).send(NGINX_404_HTML);
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
