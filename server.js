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
  let token = req?.headers?.['authorization'] || req?.headers?.['auth'] || req?.headers?.['x-auth-token'] || cachedToken || process.env.DEFAULT_BEARER_TOKEN || '';

  if (token && !token.toLowerCase().startsWith('bearer ')) {
    token = `Bearer ${token.trim()}`;
  }

  const language = req?.headers?.['language'] || req?.headers?.['selected_language'] || req?.query?.language || req?.query?.selected_language || 'hindi';
  const deviceId = req?.headers?.['device-id'] || req?.headers?.['device_id'] || req?.query?.device_id || req?.query?.deviceId || 'mobile-web';
  const clientTs = req?.headers?.['client-ts'] || req?.headers?.['client_ts'] || req?.query?.client_ts || '1770000000';

  const headers = {
    'Host': 'api.pocketfm.com',
    'app-name': 'pocket_fm',
    'platform': 'android',
    'content-type': 'application/json;charset=utf-8',
    'accept': 'application/json',
    'version-name': '9.1.3',
    'platform-version': '29',
    'app-version': '2013',
    'device-id': deviceId,
    'device_id': deviceId,
    'client-ts': String(clientTs),
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
            const realAudioUrl = (story.audio_url && !story.audio_url.includes('.mpd') && !story.audio_url.includes('drm-aac')) ? story.audio_url :
                                 (story.media_url && !story.media_url.includes('.mpd') && !story.media_url.includes('drm-aac') ? story.media_url : "");
            const realMediaUrlEnc = story.media_url_enc || (story.media_url && (story.media_url.includes('.mpd') || story.media_url.includes('drm-aac')) ? story.media_url : "") || (story.audio_url && story.audio_url.includes('.mpd') ? story.audio_url : "");

            const storyObj = {
              story_title: story.story_title || story.title || "",
              show_id: story.show_id || (baseShow && baseShow.show_id) || showId,
              image_url: story.image_url || story.cover_url || (baseShow && baseShow.image_url) || "",
              duration: typeof story.duration === 'number' ? story.duration : parseFloat(story.duration || '0'),
              story_id: story.story_id || "",
              audio_url: realAudioUrl || "",
              media_url_enc: realMediaUrlEnc || "",
              media_url: realAudioUrl || realMediaUrlEnc || ""
            };

            const finalVideoUrl = webVideoUrl || (story.video_url && !story.video_url.includes('.mpd') && story.video_url.includes('.m3u8') ? story.video_url : "");
            if (finalVideoUrl) {
              storyObj.video_url = finalVideoUrl;
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

const licenseCache = new Map();

function decryptPfmBlob(clientTs, deviceId, cipherBase64) {
  const tsCandidates = [1770000000, clientTs, "1770000000"].filter(Boolean);
  const deviceCandidates = [deviceId, "mobile-web"].filter(Boolean);

  for (const dev of deviceCandidates) {
    for (const ts of tsCandidates) {
      try {
        const rawData = `${dev}:${ts}`;
        const encodedStr = Buffer.from(rawData).toString('base64');
        const chars = encodedStr.split('');
        for (let i = 0; i < chars.length - 1; i += 2) {
          const temp = chars[i];
          chars[i] = chars[i + 1];
          chars[i + 1] = temp;
        }
        const keyString = chars.join('');

        const cipherBytes = Buffer.from(cipherBase64, 'base64');
        if (cipherBytes.length < 28) continue;

        const salt = cipherBytes.subarray(0, 16);
        const iv = cipherBytes.subarray(16, 28);
        const strData = cipherBytes.subarray(28, cipherBytes.length - 16);

        const derivedKey = crypto.pbkdf2Sync(keyString, salt, 10000, 32, 'sha256');

        // In AES-GCM (96-bit nonce), the ciphertext payload is encrypted using AES-CTR starting at counter 2:
        const ctrIv = Buffer.alloc(16);
        iv.copy(ctrIv, 0, 0, 12);
        ctrIv[15] = 2;

        const decipher = crypto.createDecipheriv('aes-256-ctr', derivedKey, ctrIv);
        let decrypted = decipher.update(strData, null, 'utf8');
        decrypted += decipher.final('utf8');
        const result = decrypted.trim();
        if (result && (result.startsWith('http://') || result.startsWith('https://'))) {
          return result;
        }
      } catch (err) {
        // try next candidate
      }
    }
  }
  return null;
}

app.get(['/api/license', '/license', '/api/license_url', '/api/get_license'], async (req, res) => {
  try {
    const showId = req.headers['show_id'] || req.headers['show-id'] || req.query.show_id || req.query.showId;
    if (!showId) {
      return res.status(400).json({ success: false, error: "Missing 'show_id' parameter" });
    }

    if (licenseCache.has(showId)) {
      return res.json({ success: true, license_url: licenseCache.get(showId), cached: true });
    }

    const deviceId = req.headers['device-id'] || req.headers['device_id'] || req.query.device_id || req.query.deviceId || 'mobile-web';
    const clientTs = parseInt(req.headers['client-ts'] || req.headers['client_ts'] || req.query.client_ts || '1770000000', 10);

    const headers = buildPocketHeaders(req);
    headers['device-id'] = deviceId;
    headers['device_id'] = deviceId;
    headers['client-ts'] = String(clientTs);

    const targetUrl = `${BASE_URL}/v2/content_api/show.play_details?show_id=${encodeURIComponent(showId)}&device_id=${encodeURIComponent(deviceId)}&client_ts=${clientTs}`;
    let { statusCode, data } = await fetchViaWorkerProxy(targetUrl, headers, 'GET');

    if (data && data.blob) {
      const decryptedUrl = decryptPfmBlob(clientTs, deviceId, data.blob);
      if (decryptedUrl) {
        licenseCache.set(showId, decryptedUrl);
        return res.json({ success: true, license_url: decryptedUrl });
      }
    }

    if (data && (data.license_url || data.licenseUrl)) {
      const directUrl = data.license_url || data.licenseUrl;
      licenseCache.set(showId, directUrl);
      return res.json({ success: true, license_url: directUrl });
    }

    // Fallback attempt: Web platform headers
    const webHeaders = {
      'Host': 'api.pocketfm.com',
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'platform': 'web',
      'device-id': deviceId,
      'device_id': deviceId,
      'client-ts': String(clientTs),
      'content-type': 'application/json;charset=utf-8',
      'accept': 'application/json',
      'authorization': headers['authorization'] || ''
    };
    if (cachedCookies) webHeaders['Cookie'] = cachedCookies;

    const webRes = await fetchViaWorkerProxy(targetUrl, webHeaders, 'GET');
    if (webRes.data && webRes.data.blob) {
      const decryptedUrl = decryptPfmBlob(clientTs, deviceId, webRes.data.blob);
      if (decryptedUrl) {
        licenseCache.set(showId, decryptedUrl);
        return res.json({ success: true, license_url: decryptedUrl });
      }
    }

    if (webRes.data && (webRes.data.license_url || webRes.data.licenseUrl)) {
      const directUrl = webRes.data.license_url || webRes.data.licenseUrl;
      licenseCache.set(showId, directUrl);
      return res.json({ success: true, license_url: directUrl });
    }

    return res.status(statusCode || 500).json({
      success: false,
      error: "Failed to obtain license blob from Pocket FM",
      details: data || webRes.data
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Failed to process DRM license request',
      error: error.message
    });
  }
});

app.post(['/api/drm_license', '/api/license_proxy'], express.raw({ type: '*/*', limit: '10mb' }), async (req, res) => {
  try {
    const showId = req.headers['show_id'] || req.headers['show-id'] || req.query.show_id || req.query.showId;
    if (!showId) {
      return res.status(400).send("Missing show_id parameter");
    }

    let licenseUrl = licenseCache.get(showId);
    if (!licenseUrl) {
      const deviceId = req.headers['device-id'] || req.headers['device_id'] || req.query.device_id || 'mobile-web';
      const clientTs = 1770000000;
      const headers = buildPocketHeaders(req);
      headers['device-id'] = deviceId;
      headers['device_id'] = deviceId;
      headers['client-ts'] = String(clientTs);

      const targetUrl = `${BASE_URL}/v2/content_api/show.play_details?show_id=${encodeURIComponent(showId)}&device_id=${encodeURIComponent(deviceId)}&client_ts=${clientTs}`;
      let { data } = await fetchViaWorkerProxy(targetUrl, headers, 'GET');
      if (data && data.blob) {
        licenseUrl = decryptPfmBlob(clientTs, deviceId, data.blob);
      }
      if (!licenseUrl && data && (data.license_url || data.licenseUrl)) {
        licenseUrl = data.license_url || data.licenseUrl;
      }
      if (licenseUrl) {
        licenseCache.set(showId, licenseUrl);
      }
    }

    if (!licenseUrl) {
      return res.status(500).send("Could not resolve Widevine license URL");
    }

    // Forward the Widevine challenge to Gumlet license server
    const challengeBuffer = req.body;
    const gumletRes = await axios.post(licenseUrl, challengeBuffer, {
      headers: {
        'Content-Type': 'application/octet-stream',
        'User-Agent': 'Mozilla/5.0'
      },
      responseType: 'arraybuffer',
      timeout: 15000
    });

    res.set('Content-Type', 'application/octet-stream');
    return res.send(Buffer.from(gumletRes.data));
  } catch (err) {
    console.error("DRM License proxy error:", err.message);
    return res.status(500).send(err.message);
  }
});

app.get(['/api/stream_proxy', '/api/manifest_proxy'], async (req, res) => {
  try {
    const targetUrl = req.query.url;
    if (!targetUrl) {
      return res.status(400).send("Missing 'url' parameter");
    }

    const response = await axios.get(targetUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)',
        'Accept': '*/*'
      },
      responseType: 'text',
      timeout: 15000
    });

    let manifest = response.data;
    const baseUrlMatch = targetUrl.substring(0, targetUrl.lastIndexOf('/') + 1);

    // Rewrite relative BaseURLs so they route through media_proxy
    manifest = manifest.replace(/<BaseURL>([^<]+)<\/BaseURL>/g, (match, chunkFile) => {
      const fullChunkUrl = chunkFile.startsWith('http') ? chunkFile : `${baseUrlMatch}${chunkFile}`;
      const proxiedChunkUrl = `/api/media_proxy?url=${encodeURIComponent(fullChunkUrl)}`;
      return `<BaseURL>${proxiedChunkUrl}</BaseURL>`;
    });

    res.set({
      'Content-Type': 'application/dash+xml',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
      'Access-Control-Allow-Headers': '*'
    });
    return res.send(manifest);
  } catch (err) {
    console.error("Stream proxy error:", err.message);
    return res.status(500).send("Failed to proxy manifest: " + err.message);
  }
});

app.get(['/api/media_proxy', '/api/chunk_proxy'], async (req, res) => {
  try {
    const targetUrl = req.query.url;
    if (!targetUrl) {
      return res.status(400).send("Missing 'url' parameter");
    }

    const forwardHeaders = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)',
      'Accept': '*/*'
    };

    if (req.headers.range) {
      forwardHeaders['Range'] = req.headers.range;
    }

    const response = await axios({
      method: 'GET',
      url: targetUrl,
      headers: forwardHeaders,
      responseType: 'stream',
      validateStatus: (status) => status >= 200 && status < 400,
      timeout: 20000
    });

    res.set({
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Expose-Headers': 'Content-Range, Content-Length, Accept-Ranges'
    });

    if (response.headers['content-type']) res.set('Content-Type', response.headers['content-type']);
    if (response.headers['content-range']) res.set('Content-Range', response.headers['content-range']);
    if (response.headers['content-length']) res.set('Content-Length', response.headers['content-length']);
    if (response.headers['accept-ranges']) res.set('Accept-Ranges', response.headers['accept-ranges']);

    res.status(response.status);
    response.data.pipe(res);
  } catch (err) {
    console.error("Media proxy error:", err.message);
    return res.status(500).send("Failed to proxy media segment: " + err.message);
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
