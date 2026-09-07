const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = 'https://api.pocketfm.com';
const WORKER_PROXY_URL = 'https://curl-proxy.bruceliu-dev.workers.dev/';

let cachedCookies = '';
let cachedToken = '';
let lastFetchDate = '';
let isRefreshing = false;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

async function fetchDailyCookiesFromWebsite() {
  try {
    const targetUrl = 'https://www.pocketfm.com/';
    const webHeaders = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9,hi;q=0.8'
    };

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
    } catch (e) {}

    if (!rawSetCookie || (Array.isArray(rawSetCookie) && rawSetCookie.length === 0)) {
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
  } catch (err) {
    console.error('Error fetching daily cookies:', err.message);
  }
}

async function ensureDailySession() {
  const today = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Kolkata' }).format(new Date());
  if (lastFetchDate !== today || (!cachedCookies && !cachedToken)) {
    if (!isRefreshing) {
      isRefreshing = true;
      try {
        await fetchDailyCookiesFromWebsite();
        lastFetchDate = today;
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
    } catch (err) {}
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

app.get('/cookies', async (req, res) => {
  await ensureDailySession();
  res.status(200).json({
    status: 1,
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

    if (typeof data === 'object' && data !== null) {
      return res.status(statusCode).json(data);
    } else {
      return res.status(statusCode).send(data);
    }
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

    const queryParams = new URLSearchParams({
      query: query,
      genre: genre,
      ...req.query
    }).toString();

    const url = `${BASE_URL}/v3/search/universal.search?${queryParams}`;
    const { statusCode, data } = await fetchViaWorkerProxy(url, headers, 'GET');

    if (typeof data === 'object' && data !== null) {
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

    const currPtr = req.headers['curr_ptr'] || req.headers['curr-ptr'] || req.headers['currptr'] || req.query.curr_ptr || '0';
    const pageSource = req.headers['page_source'] || req.headers['page-source'] || req.query.page_source || 'show_detail';
    const infoLevel = req.headers['info_level'] || req.headers['info-level'] || req.query.info_level || currPtr;

    const queryParams = new URLSearchParams({
      show_id: showId,
      curr_ptr: currPtr,
      info_level: infoLevel,
      page_source: pageSource,
      ...req.query
    }).toString();

    const targetUrl = `${BASE_URL}/v2/content_api/show.get_details?${queryParams}`;
    const { statusCode, data } = await fetchViaWorkerProxy(targetUrl, headers, 'GET');

    if (typeof data === 'object' && data !== null) {
      return res.status(statusCode).json(data);
    } else {
      return res.status(statusCode).send(data);
    }
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Failed to process show details',
      error: error.message
    });
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

app.all('/api/proxy/*', (req, res) => {
  const endpointPath = req.params[0];
  const queryParams = new URLSearchParams(req.query).toString();
  const url = `${BASE_URL}/${endpointPath}${queryParams ? `?${queryParams}` : ''}`;
  return forwardToPocketFM(url, req, res);
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
