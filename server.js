const express = require('express');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = 'https://api.pocketfm.com';
const WORKER_PROXY_URL = 'https://curl-proxy.bruceliu-dev.workers.dev/';

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function buildPocketHeaders(req) {
  let token = req.headers['authorization'] || req.headers['auth'] || req.headers['x-auth-token'] || process.env.DEFAULT_BEARER_TOKEN || '';

  if (token && !token.toLowerCase().startsWith('bearer ')) {
    token = `Bearer ${token.trim()}`;
  }

  const language = req.headers['language'] || req.query.language || req.query.selected_language || 'hindi';

  return {
    'Host': 'api.pocketfm.com',
    'app-name': 'pocket_fm',
    'content-type': 'application/json;charset=utf-8',
    'accept': 'application/json',
    'version-name': '9.1.3',
    'platform-version': '29',
    'app-version': '2013',
    'language': language,
    'authorization': token,
    'accept-encoding': 'gzip',
    'User-Agent': 'okhttp/4.9.2'
  };
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
    uptime: process.uptime()
  });
});

app.get('/api/feed', (req, res) => {
  const language = req.headers['language'] || req.query.selected_language || req.query.language || 'hindi';
  const apiType = req.query.api_type || 'explore_v2';

  const queryParams = new URLSearchParams({
    api_type: apiType,
    selected_language: language,
    ...req.query
  }).toString();

  const url = `${BASE_URL}/v2/feed_api/get_feed_data?${queryParams}`;
  return forwardToPocketFM(url, req, res);
});

app.get('/api/search', (req, res) => {
  const query = req.query.query || req.query.q || '';
  const genre = req.query.genre || '';

  const queryParams = new URLSearchParams({
    query: query,
    genre: genre,
    ...req.query
  }).toString();

  const url = `${BASE_URL}/v3/search/universal.search?${queryParams}`;
  return forwardToPocketFM(url, req, res);
});

app.get(['/api/show', '/api/show/:show_id'], async (req, res) => {
  try {
    const showId = req.params.show_id || req.query.show_id;

    if (!showId) {
      return res.status(400).json({
        success: false,
        error: "Missing 'show_id'. Pass it as path param (/api/show/:id) or query param (?show_id=...)"
      });
    }

    const headers = buildPocketHeaders(req);

    if (!headers.authorization || headers.authorization === 'Bearer ') {
      return res.status(401).json({
        success: false,
        error: "Missing Authorization token. Please pass 'authorization' or 'auth' in headers."
      });
    }

    const startPtr = parseInt(req.query.curr_ptr || '0', 10);
    const pageSource = req.query.page_source || 'show_detail';
    const batchSize = Math.min(Math.max(parseInt(req.query.limit || '20', 10), 1), 50);

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

    let baseResult = null;
    const allStories = [];

    for (const item of results) {
      if (!item.resData || !item.resData.data) continue;
      const json = item.resData.data;

      if (!baseResult && json.result && Array.isArray(json.result) && json.result.length > 0) {
        baseResult = JSON.parse(JSON.stringify(json));
      }

      if (json.result && Array.isArray(json.result) && json.result[0] && Array.isArray(json.result[0].stories)) {
        for (const story of json.result[0].stories) {
          if (story && story.story_id) {
            allStories.push(story);
          }
        }
      }
    }

    if (!baseResult) {
      const firstValid = results.find(r => r.resData?.data);
      if (firstValid) {
        return res.status(firstValid.resData.statusCode || 200).json(firstValid.resData.data);
      }
      return res.status(500).json({
        success: false,
        error: 'Failed to fetch show details from Pocket FM'
      });
    }

    if (baseResult.result && baseResult.result[0]) {
      baseResult.result[0].stories = allStories;
      baseResult.result[0].next_ptr = startPtr + allStories.length;
    }

    return res.status(200).json(baseResult);
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Failed to process show details batch',
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
