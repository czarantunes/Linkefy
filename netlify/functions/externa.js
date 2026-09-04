/**
 * Linkefy Audit v4 - Integrações externas reais (Observatory + PageSpeed)
 *
 * - MDN HTTP Observatory API v2 (segurança HTTP real)
 * - Google PageSpeed Insights API (performance/Core Web Vitals reais)
 *
 * Nenhuma integração tem custo obrigatório. Requisições reais + timeout + cache.
 * Se indisponível: "[Fonte] temporariamente indisponível" - nunca inventa número.
 */

const CACHE_TTL_OBSERVATORY = 600000;     // 10 min
const CACHE_TTL_PAGESPEED = 1800000;      // 30 min - mais agressivo para não bater na quota
const OBSERVATORY_TIMEOUT = 10000;
const PAGESPEED_TIMEOUT = 15000;

const cacheObservatory = new Map();
const cachePageSpeed = new Map();

/**
 * MDN HTTP Observatory - API v2 (domínio novo desde a migração para MDN em 2024).
 * A antiga API (http-observatory.mozilla.org, com polling scan_id) foi desativada
 * em 31/10/2024. A v2 é uma ÚNICA chamada POST síncrona - sem polling.
 * Endpoint real: https://observatory-api.mdn.mozilla.net/api/v2/scan?host=HOST
 * Doc: https://github.com/mdn/mdn-http-observatory
 */
async function analisarObservatory(urlStr) {
  const host = new URL(urlStr).hostname;
  const cacheKey = 'obs:' + host;

  const cached = cacheObservatory.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_OBSERVATORY) {
    return Object.assign({}, cached.data, { origem: 'cache' });
  }

  try {
    const endpoint = 'https://observatory-api.mdn.mozilla.net/api/v2/scan?host=' + encodeURIComponent(host);
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), OBSERVATORY_TIMEOUT);
    let res;
    try {
      res = await fetch(endpoint, { method: 'POST', headers: { 'content-type': 'application/json' }, signal: ctrl.signal });
    } finally {
      clearTimeout(t);
    }

    if (!res.ok) {
      return { disponivel: false, erro: 'Observatory respondeu com HTTP ' + res.status, origem: 'observatory' };
    }

    const dados = await res.json();
    if (dados.error) {
      return { disponivel: false, erro: dados.message || dados.error, origem: 'observatory' };
    }

    const r = {
      disponivel: true,
      grade: dados.grade || 'N/A',
      score: typeof dados.score === 'number' ? dados.score : null,
      testes: {
        aprovados: typeof dados.tests_passed === 'number' ? dados.tests_passed : 0,
        reprovados: typeof dados.tests_failed === 'number' ? dados.tests_failed : 0,
        total: typeof dados.tests_quantity === 'number' ? dados.tests_quantity : 0
      },
      detailsUrl: dados.details_url || null,
      origem: 'observatory'
    };

    cacheObservatory.set(cacheKey, { data: r, timestamp: Date.now() });
    return r;
  } catch (e) {
    return { disponivel: false, erro: e.name === 'AbortError' ? 'Tempo de resposta excedido.' : e.message, origem: 'observatory' };
  }
}

/**
 * Google PageSpeed Insights.
 * Endpoint: https://www.googleapis.com/pagespeedonline/v5/runPagespeed
 * Sem API key: quota compartilhada e baixa (~poucas centenas/dia por IP de origem) -
 * por isso o cache aqui é de 30 min, bem mais agressivo que o do scanner próprio,
 * para reduzir a chance de bater em HTTP 429 em uso comercial.
 */
async function analisarPageSpeed(urlStr, strategy) {
  strategy = strategy || 'mobile';
  const url = new URL(urlStr).toString();
  const cacheKey = 'psi:' + url + ':' + strategy;

  const cached = cachePageSpeed.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_PAGESPEED) {
    return Object.assign({}, cached.data, { origem: 'cache' });
  }

  try {
    const endpoint = new URL('https://www.googleapis.com/pagespeedonline/v5/runPagespeed');
    endpoint.searchParams.append('url', url);
    endpoint.searchParams.append('strategy', strategy);
    endpoint.searchParams.append('category', 'performance');
    endpoint.searchParams.append('category', 'accessibility');
    endpoint.searchParams.append('category', 'best-practices');
    endpoint.searchParams.append('category', 'seo');

    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), PAGESPEED_TIMEOUT);
    let res;
    try {
      res = await fetch(endpoint.toString(), { signal: ctrl.signal });
    } finally {
      clearTimeout(t);
    }

    if (!res.ok) {
      if (res.status === 429) {
        return { disponivel: false, erro: 'Quota do PageSpeed excedida.', origem: 'pagespeed' };
      }
      return { disponivel: false, erro: 'PageSpeed respondeu com HTTP ' + res.status, origem: 'pagespeed' };
    }

    const dados = await res.json();
    const metricas = dados.lighthouseResult || {};
    const cat = metricas.categories || {};
    const aud = metricas.audits || {};

    const r = {
      disponivel: true,
      strategy: strategy,
      scores: {
        performance: cat.performance && typeof cat.performance.score === 'number' ? Math.round(cat.performance.score * 100) : null,
        accessibility: cat.accessibility && typeof cat.accessibility.score === 'number' ? Math.round(cat.accessibility.score * 100) : null,
        bestPractices: cat['best-practices'] && typeof cat['best-practices'].score === 'number' ? Math.round(cat['best-practices'].score * 100) : null,
        seo: cat.seo && typeof cat.seo.score === 'number' ? Math.round(cat.seo.score * 100) : null
      },
      cwv: {
        lcp: (aud['largest-contentful-paint'] && aud['largest-contentful-paint'].displayValue) || 'Não disponível',
        cls: (aud['cumulative-layout-shift'] && aud['cumulative-layout-shift'].displayValue) || 'Não disponível',
        inp: (aud['interaction-to-next-paint'] && aud['interaction-to-next-paint'].displayValue) || 'Não disponível',
        fcp: (aud['first-contentful-paint'] && aud['first-contentful-paint'].displayValue) || 'Não disponível',
        ttfb: (aud['server-response-time'] && aud['server-response-time'].displayValue) || 'Não disponível'
      },
      origem: 'pagespeed'
    };

    cachePageSpeed.set(cacheKey, { data: r, timestamp: Date.now() });
    return r;
  } catch (e) {
    return { disponivel: false, erro: e.name === 'AbortError' ? 'Tempo de resposta excedido.' : e.message, origem: 'pagespeed' };
  }
}

function normalizarEvidencias(scanner, observatory, pagespeed) {
  return {
    scanner: { timestamp: new Date().toISOString(), categories: scanner },
    observatory: observatory,
    pagespeed: pagespeed,
    fontes: [
      'Scanner Linkefy',
      ...(observatory.disponivel ? ['MDN HTTP Observatory'] : []),
      ...(pagespeed.disponivel ? ['Google PageSpeed Insights'] : [])
    ]
  };
}

module.exports = {
  analisarObservatory,
  analisarPageSpeed,
  normalizarEvidencias,
  CACHE_TTL_OBSERVATORY,
  CACHE_TTL_PAGESPEED,
  OBSERVATORY_TIMEOUT,
  PAGESPEED_TIMEOUT
};
