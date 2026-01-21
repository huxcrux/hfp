import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 4173;

app.use(express.json({ limit: '1mb' }));

const getClientIp = (req) => {
  const forwardedFor = req.get('x-forwarded-for');
  const remoteAddress = req.socket?.remoteAddress;
  return forwardedFor?.split(',')[0]?.trim() || remoteAddress || 'unknown';
};

// Header-only bot analysis (for requests without browser data, like curl)
const analyzeHeadersOnly = (headers) => {
  const signals = [];
  let score = 0;

  const addSignal = (name, detected, weight, passReason, failReason) => {
    if (detected) {
      signals.push({ name, detected: true, weight, reason: failReason });
      score += weight;
    } else {
      signals.push({ name, detected: false, weight, reason: passReason });
    }
  };

  const userAgent = headers['user-agent'] || '';
  const userAgentLower = userAgent.toLowerCase();

  // No User-Agent at all
  addSignal('noUserAgent', !userAgent, 30,
    'User-Agent header present',
    'No User-Agent header (very suspicious)');

  // Short User-Agent
  addSignal('shortUserAgent', userAgent.length > 0 && userAgent.length < 20, 15,
    `User-Agent length: ${userAgent.length} chars`,
    `User-Agent too short: ${userAgent.length} chars`);

  // Bot patterns in UA
  const botPatterns = [
    'python', 'curl', 'wget', 'axios', 'node-fetch', 'go-http', 'java/',
    'libwww', 'httpunit', 'nutch', 'phpcrawl', 'msnbot', 'jyxobot',
    'fast-webcrawler', 'biglotron', 'teoma', 'convera', 'gigablast',
    'ia_archiver', 'webmon', 'httrack', 'grub.org', 'netresearchserver',
    'speedy', 'fluffy', 'findlink', 'panscient', 'ips-agent', 'yanga',
    'cyberpatrol', 'postrank', 'page2rss', 'linkdex', 'ezooms', 'heritrix',
    'findthatfile', 'europarchive.org', 'mappydata', 'eright', 'apercite',
    'scrapy', 'mechanize', 'phantom', 'casper', 'selenium', 'webdriver',
    'chrome-lighthouse', 'pingdom', 'phantomjs', 'headlesschrome',
    'httpie', 'postman', 'insomnia', 'rest-client', 'okhttp', 'apache-http',
  ];
  const matchedBotPattern = botPatterns.find(p => userAgentLower.includes(p));
  addSignal('botUserAgent', !!matchedBotPattern, 30,
    'User-Agent appears legitimate',
    `Bot-like User-Agent pattern: ${matchedBotPattern}`);

  // Headless in UA
  addSignal('headlessUA', userAgentLower.includes('headless'), 25,
    'No headless indicator in User-Agent',
    'Headless mentioned in User-Agent');

  // No Accept header
  addSignal('noAcceptHeader', !headers['accept'], 10,
    'Accept header present',
    'Accept header missing');

  // Non-browser Accept header
  const accept = headers['accept'] || '';
  const nonBrowserAccept = accept && !accept.includes('text/html') && !accept.includes('*/*');
  addSignal('nonBrowserAccept', nonBrowserAccept, 10,
    'Accept header looks like browser',
    `Non-browser Accept header: ${accept.substring(0, 50)}`);

  // No Accept-Language header
  addSignal('noAcceptLanguage', !headers['accept-language'], 15,
    'Accept-Language header present',
    'Accept-Language header missing');

  // No Accept-Encoding header
  addSignal('noAcceptEncoding', !headers['accept-encoding'], 10,
    'Accept-Encoding header present',
    'Accept-Encoding header missing');

  // No Sec-Fetch headers (modern browsers send these)
  const hasSecFetch = headers['sec-fetch-dest'] || headers['sec-fetch-mode'] || headers['sec-fetch-site'];
  addSignal('noSecFetch', !hasSecFetch, 15,
    'Sec-Fetch headers present',
    'Sec-Fetch headers missing (not a modern browser)');

  // No Sec-CH-UA (Chrome/Edge client hints)
  addSignal('noSecChUa', !headers['sec-ch-ua'], 8,
    'Sec-CH-UA header present',
    'Sec-CH-UA header missing');

  // No Connection header
  addSignal('noConnection', !headers['connection'], 5,
    'Connection header present',
    'Connection header missing');

  // Check for upgrade-insecure-requests (browsers send this)
  addSignal('noUpgradeInsecure', !headers['upgrade-insecure-requests'], 5,
    'Upgrade-Insecure-Requests header present',
    'Upgrade-Insecure-Requests header missing');

  // DNT header (privacy-focused browsers often send this)
  // Note: absence is not necessarily suspicious, just a signal

  // Calculate verdict
  const maxScore = 100;
  const normalizedScore = Math.min(score, maxScore);

  let verdict = 'human';
  if (normalizedScore >= 50) {
    verdict = 'bot';
  } else if (normalizedScore >= 25) {
    verdict = 'suspicious';
  }

  return {
    verdict,
    score: normalizedScore,
    maxScore,
    confidence: normalizedScore >= 50 ? 'high' : normalizedScore >= 25 ? 'medium' : 'low',
    signals: signals.filter(s => s.detected),
    allSignals: signals,
    summary: {
      totalChecks: signals.length,
      flagged: signals.filter(s => s.detected).length,
      passed: signals.filter(s => !s.detected).length,
    },
  };
};

// Track page visits to detect clients that fetch HTML but never execute JS
const pageVisits = new Map(); // ip -> { timestamp, completed: boolean, botApiCalled: boolean, timeoutId: NodeJS.Timeout }
const VISIT_TTL = 5000; // 5 seconds to complete JS challenge

const deliverBotVerdict = (ip, reason) => {
  const visit = pageVisits.get(ip);
  if (!visit || visit.completed) return; // Already completed or cleaned up

  console.log('[bot-verdict]', JSON.stringify({
    timestamp: new Date().toISOString(),
    ip,
    verdict: 'bot',
    score: 100,
    code: 1006,
    reason,
    botApiCalled: visit.botApiCalled,
    challengeCompleted: visit.completed,
  }));

  // Mark as completed so we don't deliver again
  visit.completed = true;
  visit.finalVerdict = {
    verdict: 'bot',
    score: 100,
    maxScore: 100,
    code: 1006,
    confidence: 'high',
    reason,
    signals: [{
      name: 'noJsExecution',
      detected: true,
      weight: 100,
      reason,
      category: 'automation',
    }],
    allSignals: [{
      name: 'noJsExecution',
      detected: true,
      weight: 100,
      reason,
      category: 'automation',
    }],
    signalsByCategory: {
      automation: [{
        name: 'noJsExecution',
        detected: true,
        weight: 100,
        reason,
        category: 'automation',
      }],
    },
    summary: {
      totalChecks: 1,
      flagged: 1,
      passed: 0,
    },
  };
};

const trackPageVisit = (ip) => {
  // Clear any existing timeout for this IP
  const existingVisit = pageVisits.get(ip);
  if (existingVisit?.timeoutId) {
    clearTimeout(existingVisit.timeoutId);
  }

  // Set up timeout to deliver bot verdict if /api/bot is never called
  const timeoutId = setTimeout(() => {
    const visit = pageVisits.get(ip);
    if (visit && !visit.botApiCalled) {
      deliverBotVerdict(ip, 'Fetched page but never called /api/bot within 5 seconds (no JS execution)');
    }
  }, VISIT_TTL);

  pageVisits.set(ip, {
    timestamp: Date.now(),
    completed: false,
    botApiCalled: false,
    timeoutId,
    finalVerdict: null,
  });

  // Clean up old entries (entries older than 60 seconds)
  for (const [visitIp, visit] of pageVisits.entries()) {
    if (Date.now() - visit.timestamp > 60000) {
      if (visit.timeoutId) clearTimeout(visit.timeoutId);
      pageVisits.delete(visitIp);
    }
  }
};

const markBotApiCalled = (ip) => {
  const visit = pageVisits.get(ip);
  if (visit) {
    visit.botApiCalled = true;
    // Clear the timeout since they called the API
    if (visit.timeoutId) {
      clearTimeout(visit.timeoutId);
      visit.timeoutId = null;
    }
  }
};

const markVisitComplete = (ip) => {
  const visit = pageVisits.get(ip);
  if (visit) {
    visit.completed = true;
  }
};

// Get verdict for a visit - returns bot if /api/bot was never called
const getVisitVerdict = (ip) => {
  const visit = pageVisits.get(ip);
  if (!visit) {
    return { verdict: 'unknown', reason: 'No visit tracked for this IP' };
  }

  // If we already delivered a final verdict, return it
  if (visit.finalVerdict) {
    return visit.finalVerdict;
  }

  const elapsed = Date.now() - visit.timestamp;

  if (visit.completed && visit.botApiCalled) {
    return { verdict: 'pending-analysis', reason: 'Visit complete, awaiting full analysis' };
  }

  if (!visit.botApiCalled) {
    if (elapsed > VISIT_TTL) {
      return { verdict: 'bot', code: 1006, reason: 'Never called /api/bot - no JS execution' };
    }
    return { verdict: 'pending', reason: `Waiting for /api/bot call (${Math.round((VISIT_TTL - elapsed) / 1000)}s remaining)` };
  }

  return { verdict: 'pending', reason: 'Bot API called, awaiting completion' };
};

const logVisit = ({ req, browserData = null, note = 'n/a' }) => {
  const ip = getClientIp(req);
  const timestamp = new Date().toISOString();

  // Collect all request headers
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    headers[key] = value;
  }

  const logData = {
    timestamp,
    ip,
    note,
    headers,
    browserData,
  };

  console.log('[visit]', JSON.stringify(logData, null, 2));
};

// JavaScript challenge system - proves JS execution capability
const challenges = new Map(); // Store active challenges
const CHALLENGE_TTL = 60000; // 60 seconds

// Generate a challenge that requires JS to solve
app.get('/api/challenge', (req, res) => {
  const challengeId = Math.random().toString(36).substring(2, 15);
  const timestamp = Date.now();

  // Simple math challenge that requires JS execution
  const a = Math.floor(Math.random() * 100);
  const b = Math.floor(Math.random() * 100);
  const operation = ['+', '*', '-'][Math.floor(Math.random() * 3)];

  let expectedAnswer;
  switch (operation) {
    case '+': expectedAnswer = a + b; break;
    case '*': expectedAnswer = a * b; break;
    case '-': expectedAnswer = a - b; break;
  }

  // Store the challenge with expected answer
  challenges.set(challengeId, {
    expectedAnswer,
    timestamp,
    ip: getClientIp(req),
  });

  // Clean up old challenges
  for (const [id, challenge] of challenges.entries()) {
    if (Date.now() - challenge.timestamp > CHALLENGE_TTL) {
      challenges.delete(id);
    }
  }

  // Return challenge as JavaScript code that must be executed
  res.json({
    challengeId,
    // The challenge is returned as a string of JS code
    challenge: `(function() { return ${a} ${operation} ${b}; })()`,
    // Also include a more complex challenge requiring DOM/timing
    timingChallenge: timestamp,
  });
});

// Verify a challenge solution
app.post('/api/challenge/verify', (req, res) => {
  const { challengeId, answer, timingProof, executionTime } = req.body;

  const challenge = challenges.get(challengeId);

  if (!challenge) {
    return res.json({
      valid: false,
      reason: 'Challenge not found or expired',
    });
  }

  const isCorrect = answer === challenge.expectedAnswer;
  const timeDiff = Date.now() - challenge.timestamp;

  // Check if timing proof is reasonable (should be close to timingChallenge + some execution time)
  const timingValid = timingProof &&
                      Math.abs(timingProof - challenge.timestamp) < 1000 && // Within 1 second of original
                      executionTime > 0 && executionTime < 5000; // Execution took between 0-5 seconds

  // Delete used challenge
  challenges.delete(challengeId);

  const result = {
    valid: isCorrect,
    timingValid,
    executionTime,
    solveTime: timeDiff,
  };

  console.log('[challenge-verify]', JSON.stringify({
    timestamp: new Date().toISOString(),
    ip: getClientIp(req),
    challengeId,
    ...result,
  }));

  res.json(result);
});

// Middleware to analyze all incoming requests using headers only
app.use((req, _res, next) => {
  // Skip static assets and API calls that will have their own logging
  const isStaticAsset = path.extname(req.path) && !req.path.endsWith('.html');
  const isBotApiCall = req.path === '/api/bot';
  const isApiCall = req.path.startsWith('/api/');

  // Track page visits (HTML document requests)
  const isDocumentRequest = req.method === 'GET' &&
    !isStaticAsset &&
    !isApiCall &&
    (req.headers['sec-fetch-dest'] === 'document' || req.headers['accept']?.includes('text/html'));

  if (isDocumentRequest) {
    trackPageVisit(getClientIp(req));

    // For document requests, headers alone cannot prove human - needs JS execution
    console.log('[header-analysis]', JSON.stringify({
      timestamp: new Date().toISOString(),
      ip: getClientIp(req),
      method: req.method,
      path: req.path,
      verdict: 'pending',
      note: 'Awaiting JS challenge completion - headers alone cannot verify human',
      userAgent: req.headers['user-agent'] || 'none',
    }));
  } else if (!isStaticAsset && !isBotApiCall) {
    const analysis = analyzeHeadersOnly(req.headers);

    console.log('[header-analysis]', JSON.stringify({
      timestamp: new Date().toISOString(),
      ip: getClientIp(req),
      method: req.method,
      path: req.path,
      verdict: analysis.verdict,
      score: analysis.score,
      flaggedSignals: analysis.signals.map(s => s.name),
      userAgent: req.headers['user-agent'] || 'none',
    }));
  }

  next();
});

app.post('/api/visit', (req, res) => {
  const browserData = req.body ?? {};

  logVisit({
    req,
    browserData,
    note: 'client-metrics',
  });

  res.sendStatus(204);
});

// Bot detection analysis
const analyzeBotSignals = (browserData, headers) => {
  const signals = [];
  let score = 0;

  // Helper to add signal
  const addSignal = (name, detected, weight, passReason, failReason, category = 'general') => {
    if (detected) {
      signals.push({ name, detected: true, weight, reason: failReason, category });
      score += weight;
    } else {
      signals.push({ name, detected: false, weight, reason: passReason, category });
    }
  };

  // Extract common values
  const userAgent = browserData?.navigator?.userAgent || '';
  const headerUA = headers['user-agent'] || '';
  const isChrome = userAgent.includes('Chrome');
  const isFirefox = userAgent.includes('Firefox');
  const isSafari = userAgent.includes('Safari') && !isChrome;
  const isMobileUA = /mobile|android|iphone|ipad/i.test(userAgent);
  const platform = browserData?.navigator?.platform || '';
  const platformLower = platform.toLowerCase();
  const vendor = browserData?.navigator?.vendor || '';

  // === CRITICAL SIGNALS (high weight) ===

  // WebDriver flag
  const webdriverDetected = browserData?.navigator?.webdriver === true || browserData?.features?.webdriver === true;
  addSignal('webdriver', webdriverDetected, 30,
    'navigator.webdriver is false',
    'navigator.webdriver is true (automation detected)',
    'automation');

  // Automation frameworks
  addSignal('phantom', !!browserData?.features?.phantom, 30,
    'PhantomJS not detected',
    'PhantomJS detected',
    'automation');

  addSignal('nightmare', !!browserData?.features?.nightmare, 30,
    'Nightmare.js not detected',
    'Nightmare.js detected',
    'automation');

  addSignal('selenium', !!browserData?.features?.selenium, 30,
    'Selenium markers not detected',
    'Selenium markers detected',
    'automation');

  addSignal('domAutomation', !!browserData?.features?.domAutomation, 30,
    'DOM automation attribute not detected',
    'DOM automation attribute detected',
    'automation');

  // JavaScript challenge - proves JS execution capability
  const jsChallenge = browserData?.jsChallenge;
  const jsChallengeValid = jsChallenge?.valid === true;
  addSignal('jsChallengeFailed', !jsChallengeValid, 35,
    `JS challenge passed (solved in ${jsChallenge?.solveTime || 0}ms)`,
    jsChallenge ? `JS challenge failed: ${jsChallenge.reason || 'incorrect answer'}` : 'No JS challenge completed (curl/bot)',
    'automation');

  // Check for suspicious challenge timing (too slow = manual intervention or lag)
  // Note: fast times are fine - modern browsers solve simple math in <5ms
  if (jsChallenge?.valid) {
    const suspiciousTiming = jsChallenge.solveTime > 30000;
    addSignal('jsChallengeTimingSuspicious', suspiciousTiming, 10,
      `Challenge solved in ${jsChallenge.solveTime}ms`,
      `Challenge took too long: ${jsChallenge.solveTime}ms (possible manual solving)`,
      'timing');
  }

  // === ESSENTIAL BROWSER DATA CHECK ===
  // Real browsers MUST provide these - if missing, definitely not a browser

  // Check for essential data that only JS in a browser can provide
  const hasScreenData = browserData?.screen?.width > 0 && browserData?.screen?.height > 0;
  const hasWindowData = browserData?.window?.innerWidth > 0 || browserData?.window?.outerWidth > 0;
  const hasNavigatorData = browserData?.navigator?.userAgent && browserData?.navigator?.language;
  const hasTimezoneData = browserData?.timezone?.timezone || browserData?.timezone?.offset !== undefined;

  // No browser data at all - instant bot detection
  const noBrowserDataAtAll = !browserData?.screen && !browserData?.window && !browserData?.navigator;
  addSignal('noBrowserData', noBrowserDataAtAll, 50,
    'Browser data present',
    'No browser data submitted (request without JS execution)',
    'automation');

  // Missing essential screen info
  addSignal('noScreenData', !hasScreenData && !noBrowserDataAtAll, 25,
    `Screen data available: ${browserData?.screen?.width}x${browserData?.screen?.height}`,
    'Screen dimensions missing or zero',
    'browser-features');

  // Missing essential window info
  addSignal('noWindowData', !hasWindowData && !noBrowserDataAtAll, 20,
    'Window data available',
    'Window dimensions missing',
    'browser-features');

  // Missing essential navigator info
  addSignal('noNavigatorData', !hasNavigatorData && !noBrowserDataAtAll, 25,
    'Navigator data available',
    'Navigator userAgent or language missing',
    'browser-features');

  // Missing timezone (all browsers have this)
  addSignal('noTimezoneData', !hasTimezoneData && !noBrowserDataAtAll, 15,
    'Timezone data available',
    'Timezone information missing',
    'browser-features');

  // === STRONG SIGNALS (medium-high weight) ===

  // Plugins
  const pluginsLength = browserData?.features?.pluginsLength ?? browserData?.plugins?.length ?? 0;
  addSignal('noPlugins', pluginsLength === 0, 15,
    `${pluginsLength} plugins detected`,
    'No browser plugins detected',
    'browser-features');

  // Languages
  const hasLanguages = browserData?.navigator?.languages?.length > 0;
  addSignal('noLanguages', !hasLanguages, 15,
    `${browserData?.navigator?.languages?.length || 0} languages configured`,
    'navigator.languages is empty',
    'browser-features');

  // Chrome object
  if (isChrome) {
    addSignal('missingChrome', !browserData?.features?.windowChrome, 20,
      'window.chrome object present',
      'Chrome UA but window.chrome missing',
      'consistency');
  }

  // Headless UA
  addSignal('headlessUA', userAgent.toLowerCase().includes('headless'), 25,
    'No headless indicator in User-Agent',
    'Headless mentioned in User-Agent',
    'automation');

  // === MEDIUM SIGNALS ===

  // Permissions API
  addSignal('noPermissionsAPI', !browserData?.features?.permissionsQuery, 10,
    'Permissions API available',
    'Permissions API not available',
    'browser-features');

  // WebGL renderer
  const webglRenderer = browserData?.webgl?.unmaskedRenderer || browserData?.webgl?.renderer || '';
  const webglRendererLower = webglRenderer.toLowerCase();
  const isSoftwareRenderer = webglRendererLower.includes('swiftshader') ||
                            webglRendererLower.includes('llvmpipe') ||
                            webglRendererLower.includes('mesa');
  addSignal('softwareRenderer', isSoftwareRenderer, 20,
    `Hardware renderer: ${webglRenderer || 'detected'}`,
    `Software renderer detected: ${webglRenderer}`,
    'webgl');

  // WebGL renderer missing
  const noWebGLRenderer = !webglRenderer && browserData?.webgl && !browserData?.webgl?.error;
  addSignal('noWebGLRenderer', noWebGLRenderer, 10,
    `WebGL renderer: ${webglRenderer || 'available'}`,
    'WebGL available but no renderer info',
    'webgl');

  // WebGL vendor
  const webglVendor = browserData?.webgl?.unmaskedVendor || browserData?.webgl?.vendor || '';
  const isSoftwareVendor = webglVendor.toLowerCase().includes('brian paul') ||
                          webglVendor.toLowerCase().includes('mesa');
  addSignal('softwareVendor', isSoftwareVendor, 15,
    `WebGL vendor: ${webglVendor || 'hardware'}`,
    `Software WebGL vendor: ${webglVendor}`,
    'webgl');

  // WebGL extensions
  const webglExtensions = browserData?.webgl?.extensions || [];
  const hasWebGLExtensions = Array.isArray(webglExtensions) && webglExtensions.length > 0;
  addSignal('noWebGLExtensions', !hasWebGLExtensions, 8,
    `${webglExtensions.length} WebGL extensions available`,
    'No WebGL extensions available',
    'webgl');

  // Screen dimensions
  const screenWidth = browserData?.screen?.width || 0;
  const screenHeight = browserData?.screen?.height || 0;
  addSignal('zeroScreenSize', screenWidth === 0 || screenHeight === 0, 15,
    `Screen: ${screenWidth}x${screenHeight}`,
    'Screen dimensions are zero',
    'screen');

  addSignal('defaultScreenSize', screenWidth === 800 && screenHeight === 600, 10,
    `Screen: ${screenWidth}x${screenHeight}`,
    'Default 800x600 screen (common in bots)',
    'screen');

  // Window chrome
  const innerWidth = browserData?.window?.innerWidth || 0;
  const outerWidth = browserData?.window?.outerWidth || 0;
  const innerHeight = browserData?.window?.innerHeight || 0;
  const outerHeight = browserData?.window?.outerHeight || 0;
  const noWindowChrome = outerWidth > 0 && innerWidth > 0 &&
                        outerWidth === innerWidth && outerHeight === innerHeight;
  addSignal('noWindowChrome', noWindowChrome, 10,
    `Window chrome detected (outer: ${outerWidth}x${outerHeight}, inner: ${innerWidth}x${innerHeight})`,
    'innerWidth/Height equals outerWidth/Height (no browser chrome)',
    'screen');

  // Notification API
  addSignal('noNotifications', !browserData?.features?.notifications, 5,
    'Notification API available',
    'Notification API not available',
    'browser-features');

  // WebRTC
  addSignal('noWebRTC', !browserData?.features?.webRTC, 8,
    'WebRTC available',
    'WebRTC not available',
    'browser-features');

  // IndexedDB
  addSignal('noIndexedDB', !browserData?.features?.indexedDB, 8,
    'IndexedDB available',
    'IndexedDB not available',
    'browser-features');

  // localStorage
  addSignal('noLocalStorage', !browserData?.features?.localStorage, 10,
    'localStorage available',
    'localStorage not available',
    'browser-features');

  // sessionStorage
  addSignal('noSessionStorage', !browserData?.features?.sessionStorage, 10,
    'sessionStorage available',
    'sessionStorage not available',
    'browser-features');

  // === WEAK SIGNALS ===

  // Battery API
  const hasBattery = browserData?.battery && !browserData?.battery?.error;
  addSignal('noBattery', !hasBattery, 2,
    'Battery API available',
    'Battery API not available',
    'browser-features');

  // Media devices
  const hasMediaDevices = browserData?.mediaDevices && !browserData?.mediaDevices?.error;
  addSignal('noMediaDevices', !hasMediaDevices, 5,
    'Media devices API available',
    'Media devices not available',
    'browser-features');

  // Zero media devices
  if (hasMediaDevices) {
    const totalDevices = (browserData?.mediaDevices?.audioinput || 0) +
                        (browserData?.mediaDevices?.audiooutput || 0) +
                        (browserData?.mediaDevices?.videoinput || 0);
    addSignal('zeroMediaDevices', totalDevices === 0, 8,
      `${totalDevices} media devices detected`,
      'Zero media devices detected',
      'browser-features');
  }

  // Mobile touch support
  if (isMobileUA) {
    addSignal('mobileNoTouch', browserData?.touch?.maxTouchPoints === 0, 15,
      `Touch support: ${browserData?.touch?.maxTouchPoints} touch points`,
      'Mobile UA but no touch support',
      'consistency');
  }

  // Desktop touch mismatch
  if (!isMobileUA) {
    const touchMismatch = browserData?.touch?.maxTouchPoints > 0 && !browserData?.touch?.touchEvent;
    addSignal('desktopTouchMismatch', touchMismatch, 5,
      'Touch configuration consistent',
      'Desktop UA with touch points but no touch events',
      'consistency');
  }

  // Speech voices
  const voiceCount = browserData?.speechVoices?.count || 0;
  addSignal('noSpeechVoices', voiceCount === 0, 3,
    `${voiceCount} speech voices available`,
    'No speech synthesis voices',
    'browser-features');

  // Connection API (Chrome)
  if (isChrome) {
    addSignal('noConnectionAPI', !browserData?.connection, 5,
      'Network Information API available',
      'Network Information API not available in Chrome',
      'browser-features');
  }

  // Fonts
  const fontsCount = browserData?.fonts?.length || 0;
  addSignal('noFonts', fontsCount === 0, 10,
    `${fontsCount} fonts detected`,
    'No fonts detected',
    'browser-features');

  addSignal('fewFonts', fontsCount > 0 && fontsCount < 5, 5,
    `${fontsCount} fonts detected`,
    `Only ${fontsCount} fonts detected (minimal)`,
    'browser-features');

  // Canvas
  const hasCanvas = browserData?.canvas?.hash && !browserData?.canvas?.error;
  addSignal('noCanvasHash', !hasCanvas, 8,
    'Canvas fingerprint available',
    'Canvas fingerprint unavailable',
    'browser-features');

  // Audio
  addSignal('audioError', !!browserData?.audio?.error, 5,
    'Audio context working',
    'Audio context error',
    'browser-features');

  // Performance memory (Chrome)
  if (isChrome) {
    addSignal('noPerformanceMemory', !browserData?.performance?.jsHeapSizeLimit, 5,
      'performance.memory available',
      'performance.memory not available in Chrome',
      'browser-features');
  }

  // Document hidden
  addSignal('documentHidden', browserData?.document?.hidden === true, 8,
    'Document visible during fingerprinting',
    'Document was hidden during fingerprinting',
    'browser-features');

  // Device pixel ratio
  const dpr = browserData?.screen?.devicePixelRatio;
  const unusualDPR = dpr && (dpr < 0.5 || dpr > 4);
  addSignal('unusualDPR', unusualDPR, 5,
    `devicePixelRatio: ${dpr}`,
    `Unusual devicePixelRatio: ${dpr}`,
    'screen');

  // Color depth
  const colorDepth = browserData?.screen?.colorDepth;
  addSignal('lowColorDepth', colorDepth && colorDepth < 24, 5,
    `Color depth: ${colorDepth}`,
    `Low color depth: ${colorDepth}`,
    'screen');

  // Navigator consistency
  const navInconsistent = browserData?.navigator?.appName === 'Netscape' &&
                         browserData?.navigator?.product !== 'Gecko';
  addSignal('navigatorInconsistency', navInconsistent, 5,
    'Navigator properties consistent',
    'Navigator properties inconsistent',
    'consistency');

  // Gamepad API
  addSignal('noGamepadAPI', !browserData?.gamepads?.supported, 2,
    'Gamepad API supported',
    'Gamepad API not supported',
    'browser-features');

  // Keyboard API
  addSignal('keyboardAPIError', !!browserData?.keyboard?.error, 5,
    'Keyboard API working',
    'Keyboard API error (possible automation)',
    'browser-features');

  // Service Worker
  addSignal('noServiceWorker', !browserData?.features?.serviceWorker, 3,
    'Service Worker supported',
    'Service Worker not supported',
    'browser-features');

  // WebAssembly
  addSignal('noWebAssembly', !browserData?.features?.WebAssembly, 5,
    'WebAssembly supported',
    'WebAssembly not supported',
    'browser-features');

  // Bluetooth
  addSignal('noBluetooth', !browserData?.features?.bluetooth, 2,
    'Bluetooth API available',
    'Bluetooth API not available',
    'browser-features');

  // USB
  addSignal('noUSB', !browserData?.features?.usb, 2,
    'USB API available',
    'USB API not available',
    'browser-features');

  // Credentials
  addSignal('noCredentials', !browserData?.features?.credentials, 3,
    'Credentials API available',
    'Credentials API not available',
    'browser-features');

  // === HEADER-BASED SIGNALS ===

  // Accept-Language header
  addSignal('noAcceptLanguage', !headers['accept-language'], 10,
    'Accept-Language header present',
    'Accept-Language header missing',
    'headers');

  // Accept header
  addSignal('noAcceptHeader', !headers['accept'], 5,
    'Accept header present',
    'Accept header missing',
    'headers');

  // Bot UA patterns
  const headerUALower = headerUA.toLowerCase();
  const botPatterns = [
    'python', 'curl', 'wget', 'axios', 'node-fetch', 'go-http', 'java/',
    'libwww', 'httpunit', 'nutch', 'phpcrawl', 'msnbot', 'jyxobot',
    'fast-webcrawler', 'biglotron', 'teoma', 'convera', 'gigablast',
    'ia_archiver', 'webmon', 'httrack', 'grub.org', 'netresearchserver',
    'speedy', 'fluffy', 'findlink', 'panscient', 'ips-agent', 'yanga',
    'cyberpatrol', 'postrank', 'page2rss', 'linkdex', 'ezooms', 'heritrix',
    'findthatfile', 'europarchive.org', 'mappydata', 'eright', 'apercite',
    'scrapy', 'mechanize', 'phantom', 'casper', 'selenium', 'webdriver',
    'chrome-lighthouse', 'pingdom', 'phantomjs', 'headlesschrome',
  ];
  const matchedBotPattern = botPatterns.find(p => headerUALower.includes(p));
  addSignal('botUserAgent', !!matchedBotPattern, 25,
    'User-Agent appears legitimate',
    `Bot-like User-Agent pattern: ${matchedBotPattern}`,
    'headers');

  // Short UA
  addSignal('shortUserAgent', headerUA.length < 20, 15,
    `User-Agent length: ${headerUA.length} chars`,
    `User-Agent too short: ${headerUA.length} chars`,
    'headers');

  // Sec-Fetch headers
  const hasSecFetch = headers['sec-fetch-dest'] || headers['sec-fetch-mode'];
  addSignal('noSecFetch', !hasSecFetch, 8,
    'Sec-Fetch headers present',
    'Sec-Fetch headers missing',
    'headers');

  // Sec-CH-UA (Chrome)
  if (isChrome) {
    addSignal('noSecChUa', !headers['sec-ch-ua'], 8,
      'Sec-CH-UA header present',
      'Sec-CH-UA header missing in Chrome',
      'headers');
  }

  // Connection header
  addSignal('noConnectionHeader', !headers['connection'], 3,
    'Connection header present',
    'Connection header missing',
    'headers');

  // Cache-Control header
  addSignal('noCacheControl', !headers['cache-control'], 2,
    'Cache-Control header present',
    'Cache-Control header missing',
    'headers');

  // === CONSISTENCY CHECKS ===

  // UA mismatch
  const uaMismatch = headerUA && browserData?.navigator?.userAgent &&
                    headerUA !== browserData.navigator.userAgent;
  addSignal('uaMismatch', uaMismatch, 20,
    'User-Agent header matches navigator.userAgent',
    'User-Agent header differs from navigator.userAgent',
    'consistency');

  // Language mismatch
  const acceptLanguage = headers['accept-language'] || '';
  const navigatorLanguage = browserData?.navigator?.language || '';
  let langMismatch = false;
  if (acceptLanguage && navigatorLanguage) {
    const headerLang = acceptLanguage.split(',')[0].split('-')[0].toLowerCase();
    const navLang = navigatorLanguage.split('-')[0].toLowerCase();
    langMismatch = headerLang !== navLang;
  }
  addSignal('languageMismatch', langMismatch, 10,
    'Accept-Language matches navigator.language',
    `Accept-Language differs from navigator.language`,
    'consistency');

  // Platform mismatch
  let platformMismatch = false;
  let platformMismatchReason = '';
  if (userAgent.includes('Windows') && !platformLower.includes('win')) {
    platformMismatch = true;
    platformMismatchReason = 'UA says Windows but platform differs';
  } else if (userAgent.includes('Mac') && !platformLower.includes('mac')) {
    platformMismatch = true;
    platformMismatchReason = 'UA says Mac but platform differs';
  } else if (userAgent.includes('Linux') && !platformLower.includes('linux') && !isMobileUA) {
    platformMismatch = true;
    platformMismatchReason = 'UA says Linux but platform differs';
  }
  addSignal('platformMismatch', platformMismatch, 15,
    `Platform consistent: ${platform}`,
    platformMismatchReason || 'Platform mismatch detected',
    'consistency');

  // Timezone consistency
  const timezone = browserData?.timezone?.timezone || '';
  const timezoneOffset = browserData?.timezone?.offset;
  let tzInconsistent = false;
  if (timezone && timezoneOffset !== undefined) {
    if (timezone.includes('America/') && timezoneOffset < 0) {
      tzInconsistent = true;
    } else if (timezone.includes('Europe/') && timezoneOffset > 60) {
      tzInconsistent = true;
    }
  }
  addSignal('timezoneInconsistent', tzInconsistent, 10,
    `Timezone consistent: ${timezone} (offset: ${timezoneOffset})`,
    'Timezone name and offset inconsistent',
    'consistency');

  // Client Hints mismatch
  let clientHintsMismatch = false;
  if (browserData?.userAgentData?.platform && browserData?.navigator?.platform) {
    const uadPlatform = browserData.userAgentData.platform.toLowerCase();
    if (platformLower.includes('win') && !uadPlatform.includes('win')) {
      clientHintsMismatch = true;
    }
  }
  addSignal('clientHintsMismatch', clientHintsMismatch, 15,
    'Client Hints consistent with navigator',
    'Client Hints platform differs from navigator.platform',
    'consistency');

  // Vendor mismatch
  let vendorMismatch = false;
  let vendorMismatchReason = '';
  if (isChrome && !vendor.includes('Google')) {
    vendorMismatch = true;
    vendorMismatchReason = 'Chrome UA but vendor not Google';
  } else if (isSafari && !vendor.includes('Apple')) {
    vendorMismatch = true;
    vendorMismatchReason = 'Safari UA but vendor not Apple';
  }
  addSignal('vendorMismatch', vendorMismatch, 10,
    `Vendor consistent: ${vendor}`,
    vendorMismatchReason || 'Vendor mismatch',
    'consistency');

  // Product consistency
  const productValue = browserData?.navigator?.product;
  addSignal('productInconsistent', productValue !== 'Gecko', 3,
    'navigator.product is Gecko',
    `navigator.product is ${productValue}, expected Gecko`,
    'consistency');

  // === TIMING-BASED SIGNALS ===

  const perfTiming = browserData?.performance;
  let loadTime = null;
  if (perfTiming?.navigationStart && perfTiming?.loadEventEnd) {
    loadTime = perfTiming.loadEventEnd - perfTiming.navigationStart;
  }

  addSignal('negativeLoadTime', loadTime !== null && loadTime < 0, 20,
    `Page load time: ${loadTime}ms`,
    'Negative page load time (timing manipulation)',
    'timing');

  addSignal('zeroLoadTime', loadTime === 0, 15,
    `Page load time: ${loadTime}ms`,
    'Zero page load time',
    'timing');

  // === MATH FINGERPRINT SIGNALS ===

  // Check for unusual math values (can indicate spoofing)
  const mathAcos = browserData?.math?.acos;
  const expectedAcos = 1.0471975511965979; // Math.acos(0.5)
  const mathSuspicious = mathAcos && Math.abs(mathAcos - expectedAcos) > 0.0000001;
  addSignal('mathInconsistent', mathSuspicious, 10,
    'Math functions consistent',
    'Math function results inconsistent (possible spoofing)',
    'fingerprint');

  // === WEBGL2 SIGNALS ===

  const hasWebGL2 = browserData?.webgl2 && !browserData?.webgl2?.error;
  addSignal('noWebGL2', !hasWebGL2 && isChrome, 3,
    'WebGL2 available',
    'WebGL2 not available',
    'webgl');

  // Calculate final assessment
  const maxScore = 100;
  const normalizedScore = Math.min(score, maxScore);

  let verdict = 'human';
  if (normalizedScore >= 50) {
    verdict = 'bot';
  } else if (normalizedScore >= 25) {
    verdict = 'suspicious';
  }

  // Group signals by category
  const signalsByCategory = {};
  for (const signal of signals) {
    const cat = signal.category || 'general';
    if (!signalsByCategory[cat]) {
      signalsByCategory[cat] = [];
    }
    signalsByCategory[cat].push(signal);
  }

  return {
    verdict,
    score: normalizedScore,
    maxScore,
    confidence: normalizedScore >= 50 ? 'high' : normalizedScore >= 25 ? 'medium' : 'low',
    signals: signals.filter(s => s.detected),
    allSignals: signals,
    signalsByCategory,
    summary: {
      totalChecks: signals.length,
      flagged: signals.filter(s => s.detected).length,
      passed: signals.filter(s => !s.detected).length,
    },
  };
};

// Endpoint to check visit status - useful for debugging and monitoring
app.get('/api/visit-status', (req, res) => {
  const ip = getClientIp(req);
  const verdict = getVisitVerdict(ip);

  console.log('[visit-status]', JSON.stringify({
    timestamp: new Date().toISOString(),
    ip,
    ...verdict,
  }));

  res.json(verdict);
});

app.post('/api/bot', (req, res) => {
  const browserData = req.body ?? {};
  const headers = req.headers;
  const ip = getClientIp(req);

  // Mark that this IP called the bot API (proves some JS execution)
  markBotApiCalled(ip);

  // Early rejection: No JS execution capability = definite bot
  const hasEssentialData = browserData?.screen?.width > 0 &&
                           browserData?.navigator?.userAgent &&
                           browserData?.window;
  const hasJsChallenge = browserData?.jsChallenge?.valid === true;

  if (!hasEssentialData || !hasJsChallenge) {
    const reason = !hasEssentialData
      ? 'Missing essential browser data (no JS execution)'
      : 'JS challenge not completed or failed';

    console.log('[bot-analysis]', JSON.stringify({
      timestamp: new Date().toISOString(),
      ip,
      verdict: 'bot',
      score: 100,
      code: 1005,
      reason,
    }));

    return res.json({
      verdict: 'bot',
      score: 100,
      maxScore: 100,
      code: 1005,
      confidence: 'high',
      reason,
      signals: [{
        name: 'jsExecutionFailed',
        detected: true,
        weight: 100,
        reason,
        category: 'automation',
      }],
      allSignals: [{
        name: 'jsExecutionFailed',
        detected: true,
        weight: 100,
        reason,
        category: 'automation',
      }],
      signalsByCategory: {
        automation: [{
          name: 'jsExecutionFailed',
          detected: true,
          weight: 100,
          reason,
          category: 'automation',
        }],
      },
      summary: {
        totalChecks: 1,
        flagged: 1,
        passed: 0,
      },
    });
  }

  const analysis = analyzeBotSignals(browserData, headers);

  // Mark visit as complete (JS executed successfully)
  markVisitComplete(ip);

  console.log('[bot-analysis]', JSON.stringify({
    timestamp: new Date().toISOString(),
    ip,
    verdict: analysis.verdict,
    score: analysis.score,
    flaggedSignals: analysis.signals.map(s => s.name),
  }));

  res.json(analysis);
});

const distDir = path.resolve(__dirname, 'dist');
app.use(express.static(distDir));

app.get('*', (_req, res) => {
  res.sendFile(path.join(distDir, 'index.html'));
});

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
