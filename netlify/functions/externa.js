/**
 * Linkefy Audit v2 - Extensão com integrações externas reais
 * 
 * Estende o motor Linkefy original com:
 * - MDN HTTP Observatory API (segurança HTTP real)
 * - Google PageSpeed Insights API (performance/Core Web Vitals reais)
 * 
 * Nenhuma integração tem custo obrigatório.
 * Observatory é 100% gratuito e sem limite.
 * PageSpeed é gratuito com quota padrão (150 req/min/IP).
 * 
 * Requisições reais + tratamento de erro/timeout + cache.
 * Se indisponível: "Fonte externa indisponível nesta análise."
 * Nunca substitui resposta externa por número inventado.
 */

const CACHE_TTL = 600000; // 10 min
const OBSERVATORY_TIMEOUT = 10000; // 10s
const PAGESPEED_TIMEOUT = 15000; // 15s

const cacheObservatory = new Map();
const cachePageSpeed = new Map();

/**
 * MDN HTTP Observatory
 * Endpoint: https://http-observatory.mozilla.org/api/v2/scan
 * 
 * Retorna grade (A+, A, B, C, D, E, F) e score (0-100).
 * Documentação: https://mozilla.github.io/http-observatory/
 */
async function analisarObservatory(urlStr) {
  const url = new URL(urlStr).hostname;
  const cacheKey = 'obs:' + url;
  
  // Checar cache
  const cached = cacheObservatory.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return { ...cached.data, origem: 'cache' };
  }
  
  try {
    const iniciar = new URL('https://http-observatory.mozilla.org/api/v2/scan');
    iniciar.searchParams.append('host', url);
    iniciar.searchParams.append('publish', 'false');
    
    const resIniciar = await Promise.race([
      fetch(iniciar.toString(), { method: 'POST' }),
      new Promise((_, r) => setTimeout(() => r(new Error('Observatory timeout')), OBSERVATORY_TIMEOUT))
    ]);
    
    if (!resIniciar.ok) {
      return { 
        disponivel: false, 
        erro: 'Observatory respondeu com HTTP ' + resIniciar.status,
        origem: 'observatory'
      };
    }
    
    const scan = await resIniciar.json();
    const scanId = scan.scan_id;
    if (!scanId) {
      return { disponivel: false, erro: 'Sem scan_id', origem: 'observatory' };
    }
    
    // Aguardar resultado (polling)
    let resultado = null;
    for (let i = 0; i < 20; i++) {
      const resPoll = await Promise.race([
        fetch(`https://http-observatory.mozilla.org/api/v2/scan/${scanId}`),
        new Promise((_, r) => setTimeout(() => r(new Error('Observatory timeout')), OBSERVATORY_TIMEOUT))
      ]);
      if (!resPoll.ok) continue;
      
      const dados = await resPoll.json();
      if (dados.state === 'FINISHED') {
        resultado = dados;
        break;
      }
      await new Promise(r => setTimeout(r, 500));
    }
    
    if (!resultado) {
      return { disponivel: false, erro: 'Scan não concluído', origem: 'observatory' };
    }
    
    const r = {
      disponivel: true,
      grade: resultado.grade || 'N/A',
      score: resultado.score || null,
      testes: {
        aprovados: resultado.tests ? Object.keys(resultado.tests).filter(t => resultado.tests[t].pass === true).length : 0,
        reprovados: resultado.tests ? Object.keys(resultado.tests).filter(t => resultado.tests[t].pass === false).length : 0
      },
      detalhes: resultado.tests || {},
      origem: 'observatory'
    };
    
    cacheObservatory.set(cacheKey, { data: r, timestamp: Date.now() });
    return r;
  } catch (e) {
    return { 
      disponivel: false, 
      erro: e.message,
      origem: 'observatory'
    };
  }
}

/**
 * Google PageSpeed Insights
 * Endpoint: https://www.googleapis.com/pagespeedonline/v5/runPagespeed
 * 
 * Retorna scores de performance, accessibility, best practices, SEO.
 * Core Web Vitals quando disponíveis (LCP, CLS, INP, FCP, TTFB).
 * 
 * Sem API key: 150 requisições por minuto por IP (quota padrão).
 * Com API key: 25000 por dia (adicionar ?key=YOUR_KEY se necessário).
 */
async function analisarPageSpeed(urlStr, strategy = 'mobile') {
  const url = new URL(urlStr).toString();
  const cacheKey = 'psi:' + url + ':' + strategy;
  
  // Checar cache
  const cached = cachePageSpeed.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return { ...cached.data, origem: 'cache' };
  }
  
  try {
    const endpoint = new URL('https://www.googleapis.com/pagespeedonline/v5/runPagespeed');
    endpoint.searchParams.append('url', url);
    endpoint.searchParams.append('strategy', strategy);
    endpoint.searchParams.append('category', 'performance');
    endpoint.searchParams.append('category', 'accessibility');
    endpoint.searchParams.append('category', 'best-practices');
    endpoint.searchParams.append('category', 'seo');
    
    const resPSI = await Promise.race([
      fetch(endpoint.toString()),
      new Promise((_, r) => setTimeout(() => r(new Error('PageSpeed timeout')), PAGESPEED_TIMEOUT))
    ]);
    
    if (!resPSI.ok) {
      if (resPSI.status === 429) {
        return { 
          disponivel: false, 
          erro: 'Quota de PageSpeed excedida. Tente novamente em alguns minutos.',
          origem: 'pagespeed'
        };
      }
      return { 
        disponivel: false, 
        erro: 'PageSpeed respondeu com HTTP ' + resPSI.status,
        origem: 'pagespeed'
      };
    }
    
    const dados = await resPSI.json();
    const metricas = dados.lighthouseResult || {};
    
    const r = {
      disponivel: true,
      strategy: strategy,
      scores: {
        performance: metricas.categories?.performance?.score
          ? Math.round(metricas.categories.performance.score * 100)
          : null,
        accessibility: metricas.categories?.accessibility?.score
          ? Math.round(metricas.categories.accessibility.score * 100)
          : null,
        bestPractices: metricas.categories?.['best-practices']?.score
          ? Math.round(metricas.categories['best-practices'].score * 100)
          : null,
        seo: metricas.categories?.seo?.score
          ? Math.round(metricas.categories.seo.score * 100)
          : null
      },
      cwv: {
        lcp: metricas.audits?.['largest-contentful-paint']?.displayValue || 'Não disponível',
        cls: metricas.audits?.['cumulative-layout-shift']?.displayValue || 'Não disponível',
        inp: metricas.audits?.['interaction-to-next-paint']?.displayValue || 'Não disponível',
        fcp: metricas.audits?.['first-contentful-paint']?.displayValue || 'Não disponível',
        ttfb: metricas.audits?.['server-response-time']?.displayValue || 'Não disponível'
      },
      origem: 'pagespeed'
    };
    
    cachePageSpeed.set(cacheKey, { data: r, timestamp: Date.now() });
    return r;
  } catch (e) {
    return { 
      disponivel: false, 
      erro: e.message,
      origem: 'pagespeed'
    };
  }
}

/**
 * Normalizar evidências - unifica o que veio de cada fonte
 */
function normalizarEvidencias(scanner, observatory, pagespeed) {
  return {
    scanner: {
      timestamp: new Date().toISOString(),
      categories: scanner // as 7 categorias já calculadas
    },
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
  CACHE_TTL,
  OBSERVATORY_TIMEOUT,
  PAGESPEED_TIMEOUT
};
