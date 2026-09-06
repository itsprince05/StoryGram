const express = require('express');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = 'https://api.pocketfm.com';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/**
 * Helper function to construct Pocket FM headers dynamically.
 * Client only needs to send 'authorization' (or 'auth') and optionally 'language'.
 * All other required device/platform headers are automatically attached.
 */
function buildPocketHeaders(req) {
  // Extract Authorization token
  let token = req.headers['authorization'] || req.headers['auth'] || req.headers['x-auth-token'] || process.env.DEFAULT_BEARER_TOKEN || '';

  if (token && !token.toLowerCase().startsWith('bearer ')) {
    token = `Bearer ${token.trim()}`;
  }

  // Extract language from header, or query param, or default to hindi
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

/**
 * Common request dispatcher for Pocket FM
 */
async function forwardToPocketFM(targetUrl, req, res) {
  try {
    const headers = buildPocketHeaders(req);

    if (!headers.authorization || headers.authorization === 'Bearer ') {
      return res.status(401).json({
        success: false,
        error: "Missing Authorization token. Please pass 'authorization' or 'auth' in headers."
      });
    }

    const response = await axios({
      method: req.method,
      url: targetUrl,
      headers: headers,
      params: req.query,
      data: req.method !== 'GET' ? req.body : undefined,
      timeout: 15000,
      validateStatus: () => true // Allow handling non-200 responses smoothly
    });

    return res.status(response.status).json(response.data);
  } catch (error) {
    console.error(`[Proxy Error] ${req.method} ${targetUrl} ->`, error.message);
    return res.status(error.response?.status || 500).json({
      success: false,
      message: 'Failed to fetch from Pocket FM API',
      error: error.message,
      details: error.response?.data || null
    });
  }
}

// -------------------------------------------------------------
// 1. Health / Keep-Alive Endpoint (For 1-min Cron Job)
// -------------------------------------------------------------
app.get(['/health', '/ping'], (req, res) => {
  res.status(200).json({
    status: 'online',
    message: 'API Proxy is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// -------------------------------------------------------------
// 2. Feed Data Endpoint (Explore / Feed)
// Example: GET /api/feed?api_type=explore_v2&selected_language=hindi
// -------------------------------------------------------------
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

// -------------------------------------------------------------
// 3. Universal Search Endpoint
// Example: GET /api/search?query=insta%20millionaire&genre=
// -------------------------------------------------------------
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

// -------------------------------------------------------------
// 4. Show Details Endpoint
// Example 1: GET /api/show?show_id=4befca3da259b11359969ac8d4813650c587b440&curr_ptr=100
// Example 2: GET /api/show/4befca3da259b11359969ac8d4813650c587b440
// -------------------------------------------------------------
app.get(['/api/show', '/api/show/:show_id'], (req, res) => {
  const showId = req.params.show_id || req.query.show_id;

  if (!showId) {
    return res.status(400).json({
      success: false,
      error: "Missing 'show_id'. Pass it as path param (/api/show/:id) or query param (?show_id=...)"
    });
  }

  const queryParams = new URLSearchParams({
    show_id: showId,
    curr_ptr: req.query.curr_ptr || '100',
    info_level: req.query.info_level || '100',
    page_source: req.query.page_source || 'show_detail',
    ...req.query
  }).toString();

  const url = `${BASE_URL}/v2/content_api/show.get_details?${queryParams}`;
  return forwardToPocketFM(url, req, res);
});

// -------------------------------------------------------------
// 5. Universal Dynamic Proxy (Hit ANY Pocket FM Endpoint)
// Example: GET /api/proxy/v2/content_api/episode.get_details?episode_id=...
// -------------------------------------------------------------
app.all('/api/proxy/*', (req, res) => {
  const endpointPath = req.params[0]; // captures everything after /api/proxy/
  const queryParams = new URLSearchParams(req.query).toString();
  const url = `${BASE_URL}/${endpointPath}${queryParams ? `?${queryParams}` : ''}`;
  return forwardToPocketFM(url, req, res);
});

// -------------------------------------------------------------
// 6. Home Route
// -------------------------------------------------------------
app.get('/', (req, res) => {
  res.send('Running...');
});

// Start Server
app.listen(PORT, () => {
  console.log(`=========================================`);
  console.log(`🚀 Pocket FM Proxy Server running on port ${PORT}`);
  console.log(`🌐 Base URL: http://localhost:${PORT}`);
  console.log(`💓 Keep-alive endpoint: http://localhost:${PORT}/health`);
  console.log(`=========================================`);
});
