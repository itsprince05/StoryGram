const express = require('express');
const axios = require('axios');
const cors = require('cors');
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
        const val = parts.slice(1).join('=');
        if (val.startsWith('eyJ') && val.includes('.')) {
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

    if (!data || typeof data !== 'object') {
      return res.status(statusCode).send(data);
    }

    const rawModules = Array.isArray(data.result) ? data.result : [];
    const filteredModules = [];

    for (const mod of rawModules) {
      if (!mod) continue;

      const rawEntities = Array.isArray(mod.entities) ? mod.entities : [];
      const shows = [];

      for (const ent of rawEntities) {
        if (!ent) continue;

        let showId = "";
        let title = "";
        let imageUrl = "";

        if (ent.type === 'show' && ent.value) {
          showId = ent.value.show_id || ent.value.entity_id || "";
          title = ent.value.show_title || ent.value.title || "";
          imageUrl = ent.value.image_url || ent.value.cover_url || ent.value.gift_url || "";
        } else if (ent.type === 'top_10_show' && ent.value) {
          const showInfo = ent.value.show_info || ent.value;
          showId = ent.value.show_id || showInfo.show_id || showInfo.entity_id || "";
          title = showInfo.show_title || showInfo.title || "";
          imageUrl = showInfo.image_url || showInfo.cover_url || showInfo.gift_url || "";
        } else if (ent.value) {
          const val = ent.value.show_info || ent.value;
          showId = val.show_id || val.entity_id || "";
          title = val.show_title || val.title || "";
          imageUrl = val.image_url || val.cover_url || val.gift_url || "";
        }

        if (showId || title) {
          shows.push({
            show_id: showId,
            title: title,
            image_url: imageUrl
          });
        }
      }

      if (shows.length > 0 || mod.module_name) {
        filteredModules.push({
          module_name: mod.module_name || "",
          shows: shows
        });
      }
    }

    const formattedResponse = {
      status: data.status !== undefined ? data.status : 1,
      message: data.message || "Home feed details",
      cookies: cachedCookies || "No cookies found",
      token: cachedToken || "",
      result: filteredModules
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

    const queryParams = new URLSearchParams({
      query: query,
      genre: genre,
      ...req.query
    }).toString();

    const url = `${BASE_URL}/v3/search/universal.search?${queryParams}`;
    const { statusCode, data } = await fetchViaWorkerProxy(url, headers, 'GET');

    if (!data || typeof data !== 'object') {
      return res.status(statusCode).send(data);
    }

    const rawShows = data.result?.shows || [];
    const filteredShows = [];

    for (const show of rawShows) {
      if (show && (show.entity_id || show.show_id || show.title)) {
        filteredShows.push({
          show_id: show.entity_id || show.show_id || "",
          title: show.title || show.show_title || "",
          image_url: show.image_url || show.cover_url || show.thumbnail_url || ""
        });
      }
    }

    const formattedResponse = {
      status: data.status !== undefined ? data.status : 1,
      message: data.message || "successfully fetched results",
      result: {
        shows: filteredShows
      }
    };

    return res.status(200).json(formattedResponse);
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

    for (const item of results) {
      if (!item.resData || !item.resData.data) continue;
      const json = item.resData.data;

      if (!baseShow && json.result && Array.isArray(json.result) && json.result[0]) {
        baseShow = json.result[0];
      }

      if (json.result && Array.isArray(json.result) && json.result[0] && Array.isArray(json.result[0].stories)) {
        for (const story of json.result[0].stories) {
          if (story && (story.story_id || story.story_title || story.media_url_enc || story.media_url)) {
            allStories.push({
              story_title: story.story_title || "",
              duration: typeof story.duration === 'number' ? story.duration : parseInt(story.duration || '0', 10),
              story_id: story.story_id || "",
              media_url: story.media_url_enc || story.media_url || ""
            });
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
          show_title: baseShow.show_title || "",
          image_url: baseShow.image_url || "",
          show_id: baseShow.show_id || showId,
          episodes_count: typeof baseShow.episodes_count === 'number' ? baseShow.episodes_count : parseInt(baseShow.episodes_count || '0', 10),
          stories: allStories,
          next_ptr: startPtr + allStories.length
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

    if (!data || typeof data !== 'object') {
      return res.status(statusCode).send(data);
    }

    const rawStories = data.result?.stories || [];
    const filteredStories = [];

    for (const story of rawStories) {
      if (!story) continue;

      filteredStories.push({
        story_title: story.story_title || story.title || "",
        duration: typeof story.duration === 'number' ? story.duration : parseInt(story.duration || '0', 10),
        story_id: story.story_id || "",
        media_url: story.media_url_enc || story.media_url || ""
      });
    }

    const formattedResponse = {
      status: data.status !== undefined ? data.status : 1,
      message: data.message || "Successfully fetched saved stories !!!",
      result: {
        stories: filteredStories
      }
    };

    return res.status(200).json(formattedResponse);
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
  res.send('Running...');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
