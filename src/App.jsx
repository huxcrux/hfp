import { useEffect, useRef, useState } from 'react';
import './App.css';

const collectBrowserData = async () => {
  const data = {
    // Screen & Window
    screen: {
      width: screen.width,
      height: screen.height,
      availWidth: screen.availWidth,
      availHeight: screen.availHeight,
      colorDepth: screen.colorDepth,
      pixelDepth: screen.pixelDepth,
      devicePixelRatio: window.devicePixelRatio,
      orientation: screen.orientation?.type,
      orientationAngle: screen.orientation?.angle,
    },
    window: {
      innerWidth: window.innerWidth,
      innerHeight: window.innerHeight,
      outerWidth: window.outerWidth,
      outerHeight: window.outerHeight,
      screenX: window.screenX,
      screenY: window.screenY,
      scrollX: window.scrollX,
      scrollY: window.scrollY,
      pageXOffset: window.pageXOffset,
      pageYOffset: window.pageYOffset,
      visualViewportWidth: window.visualViewport?.width,
      visualViewportHeight: window.visualViewport?.height,
      visualViewportScale: window.visualViewport?.scale,
    },

    // Navigator properties
    navigator: {
      userAgent: navigator.userAgent,
      appVersion: navigator.appVersion,
      appName: navigator.appName,
      appCodeName: navigator.appCodeName,
      product: navigator.product,
      productSub: navigator.productSub,
      language: navigator.language,
      languages: navigator.languages ? [...navigator.languages] : [],
      platform: navigator.platform,
      vendor: navigator.vendor,
      vendorSub: navigator.vendorSub,
      hardwareConcurrency: navigator.hardwareConcurrency,
      deviceMemory: navigator.deviceMemory,
      maxTouchPoints: navigator.maxTouchPoints,
      cookieEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack,
      onLine: navigator.onLine,
      pdfViewerEnabled: navigator.pdfViewerEnabled,
      javaEnabled: navigator.javaEnabled?.() ?? null,
      webdriver: navigator.webdriver,
    },

    // User Agent Client Hints (modern alternative to user-agent)
    userAgentData: null,

    // Connection info
    connection: null,

    // Battery info
    battery: null,

    // Timezone & Locale
    timezone: {
      offset: new Date().getTimezoneOffset(),
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      locale: Intl.DateTimeFormat().resolvedOptions().locale,
      dateFormat: new Date().toLocaleDateString(),
      timeFormat: new Date().toLocaleTimeString(),
      calendar: Intl.DateTimeFormat().resolvedOptions().calendar,
      numberingSystem: Intl.DateTimeFormat().resolvedOptions().numberingSystem,
    },

    // Performance timing
    performance: null,

    // WebGL info
    webgl: null,
    webgl2: null,

    // Canvas fingerprint
    canvas: null,

    // Permissions
    permissions: {},

    // Media devices
    mediaDevices: null,

    // Storage estimates
    storage: null,

    // Client Rects (useful for detecting headless)
    clientRects: null,

    // Speech voices
    speechVoices: null,

    // Plugins list
    plugins: null,

    // MIME types
    mimeTypes: null,
  };

  // User Agent Client Hints
  try {
    if (navigator.userAgentData) {
      const uaData = navigator.userAgentData;
      data.userAgentData = {
        brands: uaData.brands,
        mobile: uaData.mobile,
        platform: uaData.platform,
      };
      // Get high entropy values if available
      if (uaData.getHighEntropyValues) {
        const highEntropy = await uaData.getHighEntropyValues([
          'architecture',
          'bitness',
          'fullVersionList',
          'model',
          'platformVersion',
          'uaFullVersion',
          'wow64',
        ]);
        data.userAgentData.highEntropy = highEntropy;
      }
    }
  } catch (e) {
    data.userAgentData = { error: e.message };
  }

  // Get connection info
  if (navigator.connection) {
    data.connection = {
      effectiveType: navigator.connection.effectiveType,
      downlink: navigator.connection.downlink,
      downlinkMax: navigator.connection.downlinkMax,
      rtt: navigator.connection.rtt,
      saveData: navigator.connection.saveData,
      type: navigator.connection.type,
    };
  }

  // Get battery info
  try {
    if (navigator.getBattery) {
      const battery = await navigator.getBattery();
      data.battery = {
        charging: battery.charging,
        chargingTime: battery.chargingTime,
        dischargingTime: battery.dischargingTime,
        level: battery.level,
      };
    }
  } catch (e) {
    data.battery = { error: e.message };
  }

  // Performance timing
  try {
    const perfTiming = performance.timing || {};
    const navTiming = performance.getEntriesByType?.('navigation')?.[0] || {};
    data.performance = {
      // Navigation timing
      navigationStart: perfTiming.navigationStart,
      loadEventEnd: perfTiming.loadEventEnd,
      domContentLoadedEventEnd: perfTiming.domContentLoadedEventEnd,
      // Memory (Chrome only)
      jsHeapSizeLimit: performance.memory?.jsHeapSizeLimit,
      totalJSHeapSize: performance.memory?.totalJSHeapSize,
      usedJSHeapSize: performance.memory?.usedJSHeapSize,
      // Navigation type
      navigationType: navTiming.type,
      redirectCount: navTiming.redirectCount,
      // Time origin
      timeOrigin: performance.timeOrigin,
    };
  } catch (e) {
    data.performance = { error: e.message };
  }

  // Get WebGL info
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (gl) {
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      data.webgl = {
        vendor: gl.getParameter(gl.VENDOR),
        renderer: gl.getParameter(gl.RENDERER),
        version: gl.getParameter(gl.VERSION),
        shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        unmaskedVendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : null,
        unmaskedRenderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : null,
        maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS),
        maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
        maxCubeMapTextureSize: gl.getParameter(gl.MAX_CUBE_MAP_TEXTURE_SIZE),
        maxVertexAttribs: gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
        maxVertexUniformVectors: gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS),
        maxFragmentUniformVectors: gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS),
        maxVaryingVectors: gl.getParameter(gl.MAX_VARYING_VECTORS),
        aliasedLineWidthRange: gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE),
        aliasedPointSizeRange: gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE),
        extensions: gl.getSupportedExtensions(),
      };
    }
  } catch (e) {
    data.webgl = { error: e.message };
  }

  // WebGL2 specific info
  try {
    const canvas = document.createElement('canvas');
    const gl2 = canvas.getContext('webgl2');
    if (gl2) {
      data.webgl2 = {
        version: gl2.getParameter(gl2.VERSION),
        shadingLanguageVersion: gl2.getParameter(gl2.SHADING_LANGUAGE_VERSION),
        maxVertexUniformComponents: gl2.getParameter(gl2.MAX_VERTEX_UNIFORM_COMPONENTS),
        maxFragmentUniformComponents: gl2.getParameter(gl2.MAX_FRAGMENT_UNIFORM_COMPONENTS),
        max3DTextureSize: gl2.getParameter(gl2.MAX_3D_TEXTURE_SIZE),
        maxArrayTextureLayers: gl2.getParameter(gl2.MAX_ARRAY_TEXTURE_LAYERS),
        maxColorAttachments: gl2.getParameter(gl2.MAX_COLOR_ATTACHMENTS),
        maxDrawBuffers: gl2.getParameter(gl2.MAX_DRAW_BUFFERS),
      };
    }
  } catch (e) {
    data.webgl2 = { error: e.message };
  }

  // Canvas fingerprint
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 200;
    canvas.height = 50;
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('Bot detection POC', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('Bot detection POC', 4, 17);

    // Additional canvas tests
    ctx.globalCompositeOperation = 'multiply';
    ctx.fillStyle = 'rgb(255,0,255)';
    ctx.beginPath();
    ctx.arc(50, 50, 50, 0, Math.PI * 2, true);
    ctx.closePath();
    ctx.fill();
    ctx.fillStyle = 'rgb(0,255,255)';
    ctx.beginPath();
    ctx.arc(100, 50, 50, 0, Math.PI * 2, true);
    ctx.closePath();
    ctx.fill();

    data.canvas = {
      dataUrl: canvas.toDataURL(),
      hash: await hashString(canvas.toDataURL()),
      // Test for canvas blocking/noise
      isPointInPath: ctx.isPointInPath(50, 50),
    };
  } catch (e) {
    data.canvas = { error: e.message };
  }

  // Client Rects fingerprint (detects headless browsers)
  try {
    const div = document.createElement('div');
    div.innerHTML = '<span>test</span>';
    document.body.appendChild(div);
    const span = div.querySelector('span');
    const rect = span.getBoundingClientRect();
    data.clientRects = {
      width: rect.width,
      height: rect.height,
      x: rect.x,
      y: rect.y,
    };
    document.body.removeChild(div);
  } catch (e) {
    data.clientRects = { error: e.message };
  }

  // Check permissions
  const permissionsToCheck = [
    'geolocation', 'notifications', 'camera', 'microphone',
    'accelerometer', 'gyroscope', 'magnetometer', 'clipboard-read',
    'clipboard-write', 'payment-handler', 'midi', 'background-sync',
    'ambient-light-sensor', 'screen-wake-lock',
  ];
  for (const perm of permissionsToCheck) {
    try {
      const result = await navigator.permissions.query({ name: perm });
      data.permissions[perm] = result.state;
    } catch (e) {
      data.permissions[perm] = 'unsupported';
    }
  }

  // Get media devices
  try {
    if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
      const devices = await navigator.mediaDevices.enumerateDevices();
      data.mediaDevices = {
        audioinput: devices.filter(d => d.kind === 'audioinput').length,
        audiooutput: devices.filter(d => d.kind === 'audiooutput').length,
        videoinput: devices.filter(d => d.kind === 'videoinput').length,
        devices: devices.map(d => ({ kind: d.kind, label: d.label || 'unlabeled', groupId: d.groupId })),
      };
    }
  } catch (e) {
    data.mediaDevices = { error: e.message };
  }

  // Storage estimate
  try {
    if (navigator.storage && navigator.storage.estimate) {
      const estimate = await navigator.storage.estimate();
      data.storage = {
        quota: estimate.quota,
        usage: estimate.usage,
        persisted: await navigator.storage.persisted?.(),
      };
    }
  } catch (e) {
    data.storage = { error: e.message };
  }

  // Speech synthesis voices
  try {
    const voices = window.speechSynthesis?.getVoices?.() || [];
    data.speechVoices = {
      count: voices.length,
      voices: voices.map(v => ({ name: v.name, lang: v.lang, localService: v.localService })),
    };
  } catch (e) {
    data.speechVoices = { error: e.message };
  }

  // Plugins
  try {
    const plugins = [];
    for (let i = 0; i < navigator.plugins.length; i++) {
      const p = navigator.plugins[i];
      plugins.push({
        name: p.name,
        filename: p.filename,
        description: p.description,
      });
    }
    data.plugins = plugins;
  } catch (e) {
    data.plugins = { error: e.message };
  }

  // MIME types
  try {
    const mimeTypes = [];
    for (let i = 0; i < navigator.mimeTypes.length; i++) {
      const m = navigator.mimeTypes[i];
      mimeTypes.push({
        type: m.type,
        suffixes: m.suffixes,
        description: m.description,
      });
    }
    data.mimeTypes = mimeTypes;
  } catch (e) {
    data.mimeTypes = { error: e.message };
  }

  // Feature detection (useful for bot detection)
  data.features = {
    webdriver: navigator.webdriver,
    automationControlled: !!window.navigator.webdriver,
    phantom: !!window._phantom || !!window.callPhantom,
    nightmare: !!window.__nightmare,
    selenium: !!window.document.__selenium_unwrapped || !!window.document.__webdriver_evaluate || !!window.document.__driver_evaluate,
    domAutomation: !!window.document.documentElement.getAttribute('webdriver'),
    chromeRuntime: !!window.chrome?.runtime,
    languages: navigator.languages?.length > 0,
    pluginsLength: navigator.plugins?.length || 0,
    mimeTypesLength: navigator.mimeTypes?.length || 0,
    localStorage: (() => { try { return !!localStorage; } catch { return false; } })(),
    sessionStorage: (() => { try { return !!sessionStorage; } catch { return false; } })(),
    indexedDB: !!window.indexedDB,
    openDatabase: !!window.openDatabase,
    speechSynthesis: !!window.speechSynthesis,
    webRTC: !!window.RTCPeerConnection,
    notifications: 'Notification' in window,
    serviceWorker: 'serviceWorker' in navigator,
    bluetooth: 'bluetooth' in navigator,
    usb: 'usb' in navigator,
    vibrate: 'vibrate' in navigator,
    credentials: 'credentials' in navigator,
    requestIdleCallback: 'requestIdleCallback' in window,
    requestAnimationFrame: 'requestAnimationFrame' in window,
    Promise: typeof Promise !== 'undefined',
    Symbol: typeof Symbol !== 'undefined',
    Proxy: typeof Proxy !== 'undefined',
    Reflect: typeof Reflect !== 'undefined',
    Intl: typeof Intl !== 'undefined',
    WebAssembly: typeof WebAssembly !== 'undefined',
    SharedArrayBuffer: typeof SharedArrayBuffer !== 'undefined',
    Atomics: typeof Atomics !== 'undefined',
    BigInt: typeof BigInt !== 'undefined',
    // Check for headless indicators
    windowChrome: !!window.chrome,
    permissionsQuery: !!navigator.permissions?.query,
    pluginsUndefined: navigator.plugins === undefined,
    languagesEmpty: !navigator.languages || navigator.languages.length === 0,
  };

  // Document properties
  data.document = {
    characterSet: document.characterSet,
    compatMode: document.compatMode,
    contentType: document.contentType,
    designMode: document.designMode,
    dir: document.dir,
    doctype: document.doctype?.name,
    documentMode: document.documentMode,
    hidden: document.hidden,
    visibilityState: document.visibilityState,
    readyState: document.readyState,
    referrer: document.referrer,
    title: document.title,
    URL: document.URL,
  };

  // Audio context fingerprint
  try {
    const audioContext = new (window.AudioContext || window.webkitAudioContext)();
    const oscillator = audioContext.createOscillator();
    const analyser = audioContext.createAnalyser();
    const gainNode = audioContext.createGain();
    const scriptProcessor = audioContext.createScriptProcessor?.(4096, 1, 1);

    data.audio = {
      sampleRate: audioContext.sampleRate,
      state: audioContext.state,
      baseLatency: audioContext.baseLatency,
      outputLatency: audioContext.outputLatency,
      channelCount: audioContext.destination.channelCount,
      maxChannelCount: audioContext.destination.maxChannelCount,
      numberOfInputs: audioContext.destination.numberOfInputs,
      numberOfOutputs: audioContext.destination.numberOfOutputs,
      fftSize: analyser.fftSize,
      frequencyBinCount: analyser.frequencyBinCount,
    };
    audioContext.close();
  } catch (e) {
    data.audio = { error: e.message };
  }

  // Math fingerprint (different in some environments)
  data.math = {
    acos: Math.acos(0.5),
    acosh: Math.acosh(1e300),
    asin: Math.asin(0.5),
    asinh: Math.asinh(1),
    atan: Math.atan(0.5),
    atanh: Math.atanh(0.5),
    atan2: Math.atan2(0.5, 0.5),
    cbrt: Math.cbrt(100),
    cos: Math.cos(10),
    cosh: Math.cosh(1),
    exp: Math.exp(1),
    expm1: Math.expm1(1),
    log: Math.log(10),
    log1p: Math.log1p(10),
    log10: Math.log10(100),
    log2: Math.log2(100),
    sin: Math.sin(10),
    sinh: Math.sinh(1),
    sqrt: Math.sqrt(100),
    tan: Math.tan(10),
    tanh: Math.tanh(1),
    pow: Math.pow(Math.PI, -100),
  };

  // Error stack fingerprint
  try {
    throw new Error('test');
  } catch (e) {
    data.errorStack = {
      sample: e.stack?.substring(0, 500),
    };
  }

  // Fonts detection
  data.fonts = await detectFonts();

  // Touch support
  data.touch = {
    maxTouchPoints: navigator.maxTouchPoints,
    touchEvent: 'ontouchstart' in window,
    touchPoints: 'TouchEvent' in window,
  };

  // Gamepad API
  try {
    const gamepads = navigator.getGamepads?.() || [];
    data.gamepads = {
      supported: 'getGamepads' in navigator,
      count: Array.from(gamepads).filter(Boolean).length,
    };
  } catch (e) {
    data.gamepads = { error: e.message };
  }

  // Keyboard layout
  try {
    if (navigator.keyboard?.getLayoutMap) {
      const layoutMap = await navigator.keyboard.getLayoutMap();
      data.keyboard = {
        supported: true,
        size: layoutMap.size,
      };
    } else {
      data.keyboard = { supported: false };
    }
  } catch (e) {
    data.keyboard = { error: e.message };
  }

  return data;
};

const hashString = async (str) => {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

const detectFonts = async () => {
  const baseFonts = ['monospace', 'sans-serif', 'serif'];
  const testFonts = [
    'Arial', 'Arial Black', 'Arial Narrow', 'Arial Rounded MT Bold',
    'Book Antiqua', 'Bookman Old Style', 'Bradley Hand', 'Brush Script MT',
    'Calibri', 'Cambria', 'Cambria Math', 'Candara', 'Century', 'Century Gothic',
    'Comic Sans MS', 'Consolas', 'Constantia', 'Copperplate', 'Courier', 'Courier New',
    'Garamond', 'Geneva', 'Georgia', 'Gill Sans', 'Helvetica', 'Helvetica Neue',
    'Impact', 'Lucida Bright', 'Lucida Console', 'Lucida Grande', 'Lucida Sans',
    'Microsoft Sans Serif', 'Monaco', 'Monotype Corsiva', 'MS Gothic', 'MS PGothic',
    'MS Reference Sans Serif', 'MS Sans Serif', 'MS Serif', 'MYRIAD', 'MYRIAD PRO',
    'Palatino', 'Palatino Linotype', 'Segoe Print', 'Segoe Script', 'Segoe UI',
    'Segoe UI Light', 'Segoe UI Semibold', 'Segoe UI Symbol', 'Tahoma', 'Times',
    'Times New Roman', 'Trebuchet MS', 'Verdana', 'Wingdings', 'Wingdings 2', 'Wingdings 3',
  ];

  const testString = 'mmmmmmmmmmlli';
  const testSize = '72px';
  const detected = [];

  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');

  const getWidth = (fontFamily) => {
    ctx.font = `${testSize} ${fontFamily}`;
    return ctx.measureText(testString).width;
  };

  const baseWidths = baseFonts.map(getWidth);

  for (const font of testFonts) {
    for (let i = 0; i < baseFonts.length; i++) {
      const width = getWidth(`'${font}', ${baseFonts[i]}`);
      if (width !== baseWidths[i]) {
        detected.push(font);
        break;
      }
    }
  }

  return detected;
};

const CHALLENGE_TIMEOUT_MS = 5000; // 5 second timeout for JS challenge

export default function App() {
  const [browserData, setBrowserData] = useState(null);
  const [botAnalysis, setBotAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [analysisStatus, setAnalysisStatus] = useState('collecting'); // 'collecting' | 'challenging' | 'analyzing' | 'complete'
  const hasReported = useRef(false);
  const analysisComplete = useRef(false);

  useEffect(() => {
    const collect = async () => {
      const data = await collectBrowserData();
      setBrowserData(data);
      setLoading(false);
      setAnalysisStatus('challenging');
    };
    collect();
  }, []);

  useEffect(() => {
    if (hasReported.current || !browserData) {
      return;
    }

    hasReported.current = true;

    // Solve JavaScript challenge to prove JS execution capability
    const solveChallenge = async () => {
      try {
        const startTime = performance.now();

        // Fetch the challenge
        const challengeRes = await fetch('/api/challenge');
        const challengeData = await challengeRes.json();

        // Execute the challenge code (requires JS execution)
        // eslint-disable-next-line no-eval
        const answer = eval(challengeData.challenge);

        const executionTime = performance.now() - startTime;

        // Verify the challenge
        const verifyRes = await fetch('/api/challenge/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            challengeId: challengeData.challengeId,
            answer,
            timingProof: challengeData.timingChallenge,
            executionTime: Math.round(executionTime),
          }),
        });

        return await verifyRes.json();
      } catch (error) {
        console.warn('Challenge failed:', error);
        return { valid: false, error: error.message };
      }
    };

    // Submit bot analysis with the given data
    const submitAnalysis = async (dataWithChallenge) => {
      if (analysisComplete.current) return; // Already submitted
      analysisComplete.current = true;

      setAnalysisStatus('analyzing');

      try {
        const res = await fetch('/api/bot', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(dataWithChallenge),
        });
        const analysis = await res.json();
        setBotAnalysis(analysis);
        setAnalysisStatus('complete');
      } catch (error) {
        console.warn('Failed to get bot analysis', error);
        setAnalysisStatus('complete');
      }
    };

    // Set up timeout - if challenge doesn't complete in 5 seconds, submit as bot
    const timeoutId = setTimeout(() => {
      if (analysisComplete.current) return;

      console.warn('JS challenge timed out after 5 seconds');
      submitAnalysis({
        ...browserData,
        jsChallenge: { valid: false, error: 'Challenge timed out after 5 seconds' },
      });
    }, CHALLENGE_TIMEOUT_MS);

    // Run challenge and submit analysis
    solveChallenge()
      .then((challengeResult) => {
        clearTimeout(timeoutId);
        if (analysisComplete.current) return;

        submitAnalysis({
          ...browserData,
          jsChallenge: challengeResult,
        });
      })
      .catch((error) => {
        clearTimeout(timeoutId);
        if (analysisComplete.current) return;

        console.warn('Challenge error:', error);
        submitAnalysis({
          ...browserData,
          jsChallenge: { valid: false, error: error.message },
        });
      });

    // Only report visit in production
    if (!import.meta.env.DEV) {
      fetch('/api/visit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(browserData),
      }).catch((error) => {
        console.warn('Failed to report visit', error);
      });
    }
  }, [browserData]);

  const renderValue = (value) => {
    if (value === null || value === undefined) {
      return <span className="na">N/A</span>;
    }
    if (typeof value === 'boolean') {
      return value ? 'Yes' : 'No';
    }
    if (Array.isArray(value)) {
      if (value.length === 0) return 'None';
      if (typeof value[0] === 'object') {
        return <pre className="json-value">{JSON.stringify(value, null, 2)}</pre>;
      }
      return value.join(', ');
    }
    if (typeof value === 'object') {
      return <pre className="json-value">{JSON.stringify(value, null, 2)}</pre>;
    }
    return String(value);
  };

  const renderSection = (title, data) => {
    if (!data) return null;
    return (
      <div className="section">
        <h3>{title}</h3>
        <table className="fingerprint-table">
          <tbody>
            {Object.entries(data).map(([key, value]) => (
              <tr key={key}>
                <td className="key-cell">{key}</td>
                <td className="value-cell">{renderValue(value)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  const getVerdictColor = (verdict) => {
    switch (verdict) {
      case 'bot': return '#dc2626';
      case 'suspicious': return '#f59e0b';
      case 'human': return '#10b981';
      default: return '#6b7280';
    }
  };

  if (loading) {
    return <div className="fingerprint-container">Collecting browser data...</div>;
  }

  return (
    <div className="fingerprint-container">
      <h2>Browser Fingerprint - Bot Detection POC</h2>

      {/* Bot Analysis Results */}
      <div className="bot-analysis-section">
        <h3>Bot Detection Analysis</h3>
        {!botAnalysis ? (
          <div className="verdict-card verdict-loading" style={{ borderColor: '#6b7280' }}>
            <div className="verdict-header">
              <span className="verdict-badge" style={{ backgroundColor: '#6b7280' }}>
                {analysisStatus === 'collecting' && 'COLLECTING...'}
                {analysisStatus === 'challenging' && 'VERIFYING JS...'}
                {analysisStatus === 'analyzing' && 'ANALYZING...'}
              </span>
            </div>
            <div className="analysis-progress">
              <div className="progress-step" data-done={analysisStatus !== 'collecting'}>
                Collect browser data
              </div>
              <div className="progress-step" data-done={analysisStatus === 'analyzing' || analysisStatus === 'complete'}>
                Complete JS challenge
              </div>
              <div className="progress-step" data-done={analysisStatus === 'complete'}>
                Analyze signals
              </div>
            </div>
          </div>
        ) : (
          <div className="verdict-card" style={{ borderColor: getVerdictColor(botAnalysis.verdict) }}>
            <div className="verdict-header">
              <span
                className="verdict-badge"
                style={{ backgroundColor: getVerdictColor(botAnalysis.verdict) }}
              >
                {botAnalysis.verdict.toUpperCase()}
              </span>
              <span className="confidence-badge">
                {botAnalysis.confidence} confidence
              </span>
            </div>
            <div className="score-display">
              <div className="score-bar-container">
                <div
                  className="score-bar"
                  style={{
                    width: `${botAnalysis.score}%`,
                    backgroundColor: getVerdictColor(botAnalysis.verdict),
                  }}
                />
              </div>
              <span className="score-text">
                Suspicion Score: {botAnalysis.score} / {botAnalysis.maxScore}
              </span>
            </div>
            <div className="summary-stats">
              <span>Checks: {botAnalysis.summary.totalChecks}</span>
              <span className="flagged">Flagged: {botAnalysis.summary.flagged}</span>
              <span className="passed">Passed: {botAnalysis.summary.passed}</span>
            </div>
          </div>
        )}

        {botAnalysis && botAnalysis.signals.length > 0 && (
          <div className="signals-section">
            <h4>Flagged Signals</h4>
            <table className="signals-table">
              <thead>
                <tr>
                  <th>Signal</th>
                  <th>Weight</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {botAnalysis.signals.map((signal) => (
                  <tr key={signal.name} className="signal-flagged">
                    <td>{signal.name}</td>
                    <td>+{signal.weight}</td>
                    <td>{signal.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {botAnalysis && (
          <details className="all-signals-details">
            <summary>View All Signals ({botAnalysis.allSignals.length})</summary>
            <table className="signals-table">
              <thead>
                <tr>
                  <th>Signal</th>
                  <th>Status</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {botAnalysis.allSignals.map((signal) => (
                  <tr key={signal.name} className={signal.detected ? 'signal-flagged' : 'signal-passed'}>
                    <td>{signal.name}</td>
                    <td>{signal.detected ? 'FLAGGED' : 'OK'}</td>
                    <td>{signal.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        )}
      </div>

      {renderSection('Screen', browserData?.screen)}
      {renderSection('Window', browserData?.window)}
      {renderSection('Navigator', browserData?.navigator)}
      {renderSection('User Agent Client Hints', browserData?.userAgentData)}
      {renderSection('Connection', browserData?.connection)}
      {renderSection('Battery', browserData?.battery)}
      {renderSection('Timezone & Locale', browserData?.timezone)}
      {renderSection('Performance', browserData?.performance)}
      {renderSection('WebGL', browserData?.webgl)}
      {renderSection('WebGL2', browserData?.webgl2)}
      {renderSection('Canvas', browserData?.canvas)}
      {renderSection('Client Rects', browserData?.clientRects)}
      {renderSection('Permissions', browserData?.permissions)}
      {renderSection('Media Devices', browserData?.mediaDevices)}
      {renderSection('Storage', browserData?.storage)}
      {renderSection('Speech Voices', browserData?.speechVoices)}
      {renderSection('Features & Bot Detection', browserData?.features)}
      {renderSection('Document', browserData?.document)}
      {renderSection('Audio', browserData?.audio)}
      {renderSection('Math', browserData?.math)}
      {renderSection('Touch', browserData?.touch)}
      {renderSection('Gamepads', browserData?.gamepads)}
      {renderSection('Keyboard', browserData?.keyboard)}
      {renderSection('Error Stack', browserData?.errorStack)}

      <div className="section">
        <h3>Plugins ({browserData?.plugins?.length || 0})</h3>
        {browserData?.plugins?.length > 0 ? (
          <pre className="json-value">{JSON.stringify(browserData.plugins, null, 2)}</pre>
        ) : (
          <p>None detected</p>
        )}
      </div>

      <div className="section">
        <h3>MIME Types ({browserData?.mimeTypes?.length || 0})</h3>
        {browserData?.mimeTypes?.length > 0 ? (
          <pre className="json-value">{JSON.stringify(browserData.mimeTypes, null, 2)}</pre>
        ) : (
          <p>None detected</p>
        )}
      </div>

      <div className="section">
        <h3>Detected Fonts ({browserData?.fonts?.length || 0})</h3>
        <p>{browserData?.fonts?.join(', ') || 'None detected'}</p>
      </div>
    </div>
  );
}
