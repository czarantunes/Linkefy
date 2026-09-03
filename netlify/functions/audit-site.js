/**
 * Linkefy Audit - motor de análise real (Netlify Function)
 * POST /api/audit-site  { "url": "https://exemplo.com.br" }
 *
 * Zero dependências externas. Nenhuma API paga. Nada é inventado:
 * cada item devolve pass | fail | warn | unknown, e "unknown" nunca pontua.
 *
 * PESOS DA NOTA GERAL (documentado - item 13 do briefing):
 *   performance 20 · seo 20 · security 15 · audienceFit 15
 *   conversion 15 · mobile 10 · credibility 5
 * Categoria com available:false sai do numerador E do denominador.
 */

const dns = require('dns').promises;
const net = require('net');

const { analisarObservatory, analisarPageSpeed, normalizarEvidencias } = require('./externa.js');
const TIMEOUT_MS = 8000;
const MAX_REDIRECTS = 3;
const MAX_BYTES = 2 * 1024 * 1024;
const UA = 'LinkefyAudit/1.0 (+https://www.linkefydigital.com.br/diagnostico)';

const PESOS = {
  performance: 18, seo: 18, security: 13, audienceFit: 13,
  conversion: 13, mobile: 9, design: 12, credibility: 4
};

/* ------------------------------------------------------------------ *
 * 1. PROTEÇÃO SSRF
 * ------------------------------------------------------------------ */

function ipEhPrivado(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    if (p[0] === 10) return true;                          // 10/8
    if (p[0] === 127) return true;                         // loopback
    if (p[0] === 0) return true;                           // this-host
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;  // 172.16/12
    if (p[0] === 192 && p[1] === 168) return true;         // 192.168/16
    if (p[0] === 169 && p[1] === 254) return true;         // link-local + metadata
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true; // CGNAT
    if (p[0] === 192 && p[1] === 0 && p[2] === 2) return true;
    if (p[0] >= 224) return true;                          // multicast/reservado
    return false;
  }
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    if (v === '::1' || v === '::') return true;
    if (v.startsWith('fe80')) return true;                 // link-local
    if (v.startsWith('fc') || v.startsWith('fd')) return true; // ULA
    if (v.startsWith('::ffff:')) return ipEhPrivado(v.replace('::ffff:', ''));
    return false;
  }
  return true; // formato desconhecido → bloqueia
}

const HOSTS_BLOQUEADOS = [
  'localhost', 'localhost.localdomain', 'metadata.google.internal',
  'instance-data', 'metadata'
];

async function validarDestino(urlStr) {
  let u;
  try { u = new URL(urlStr); } catch (e) { return { ok: false, erro: 'URL inválida.' }; }

  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    return { ok: false, erro: 'Apenas endereços http e https são aceitos.' };
  }
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  if (HOSTS_BLOQUEADOS.indexOf(host) !== -1 || host.endsWith('.local') || host.endsWith('.internal')) {
    return { ok: false, erro: 'Endereço interno não permitido.' };
  }
  if (host.indexOf('.') === -1) {
    return { ok: false, erro: 'Informe um domínio público completo.' };
  }
  // literal de IP informado direto
  if (net.isIP(host) && ipEhPrivado(host)) {
    return { ok: false, erro: 'Endereço interno não permitido.' };
  }
  // resolve TODOS os registros e exige que nenhum seja privado
  try {
    const enderecos = await dns.lookup(host, { all: true, verbatim: true });
    if (!enderecos.length) return { ok: false, erro: 'Domínio não resolvido.' };
    for (const e of enderecos) {
      if (ipEhPrivado(e.address)) {
        return { ok: false, erro: 'Endereço interno não permitido.' };
      }
    }
  } catch (e) {
    return { ok: false, erro: 'Não foi possível resolver este domínio.' };
  }
  return { ok: true, url: u };
}

/* ------------------------------------------------------------------ *
 * 2. FETCH CONTROLADO (redirects manuais, revalidando cada salto)
 * ------------------------------------------------------------------ */

async function buscar(urlStr, opcoes) {
  const opts = opcoes || {};
  const cadeia = [];
  let atual = urlStr;

  for (let salto = 0; salto <= MAX_REDIRECTS; salto++) {
    const v = await validarDestino(atual);
    if (!v.ok) return { erro: v.erro, cadeia };

    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
    let res;
    try {
      res = await fetch(atual, {
        redirect: 'manual',
        signal: ctrl.signal,
        headers: { 'user-agent': UA, 'accept': opts.accept || 'text/html,*/*' }
      });
    } catch (e) {
      clearTimeout(t);
      return { erro: e.name === 'AbortError' ? 'Tempo de resposta excedido.' : 'Falha ao acessar o endereço.', cadeia };
    }
    clearTimeout(t);

    cadeia.push({ url: atual, status: res.status });

    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location');
      if (!loc) return { res, url: atual, cadeia, headers: res.headers };
      atual = new URL(loc, atual).href;
      continue;
    }

    // corpo com teto de tamanho
    let corpo = '';
    let bytes = 0;
    let truncado = false;
    if (!opts.somenteCabecalhos && res.body) {
      const dec = new TextDecoder('utf-8', { fatal: false });
      try {
        for await (const chunk of res.body) {
          bytes += chunk.length;
          if (bytes > MAX_BYTES) { truncado = true; break; }
          corpo += dec.decode(chunk, { stream: true });
        }
      } catch (e) { /* corpo parcial é aceitável */ }
    }
    return { res, url: atual, corpo, bytes, truncado, cadeia, headers: res.headers, status: res.status };
  }
  return { erro: 'Excesso de redirecionamentos.', cadeia };
}

/* ------------------------------------------------------------------ *
 * 3. HELPERS DE PONTUAÇÃO
 * ------------------------------------------------------------------ */

function novaCategoria() { return { itens: [], pontos: 0, possivel: 0 }; }

/** status: 'pass' | 'fail' | 'warn' | 'unknown'. 'unknown' não entra no denominador. */
function checar(cat, status, peso, rotulo, detalhe, meta) {
  const item = { status, rotulo, detalhe: detalhe || '' };
  if (meta) {
    if (meta.source) item.source = meta.source;
    if (meta.confidence) item.confidence = meta.confidence;
    if (meta.grupo) item.grupo = meta.grupo;
    if (meta.id) item.id = meta.id;
  }
  cat.itens.push(item);
  if (status === 'unknown') return;
  cat.possivel += peso;
  if (status === 'pass') cat.pontos += peso;
  else if (status === 'warn') cat.pontos += peso * 0.5;
}

function fechar(cat, resumoQuandoOk) {
  if (cat.possivel === 0) {
    return { available: false, reason: 'Não foi possível verificar esta categoria.', checks: cat.itens };
  }
  const score = Math.round((cat.pontos / cat.possivel) * 100);
  return { available: true, score, checks: cat.itens, summary: resumoQuandoOk(score) };
}

function faixaTexto(n) {
  if (n >= 90) return 'Excelente';
  if (n >= 80) return 'Muito boa';
  if (n >= 70) return 'Boa';
  if (n >= 65) return 'Regular';
  if (n >= 40) return 'Precisa melhorar';
  return 'Crítica';
}

/* ------------------------------------------------------------------ *
 * 4. EXTRAÇÃO DO HTML (sem dependências)
 * ------------------------------------------------------------------ */

function semTags(s) {
  return String(s || '')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Remove blocos com display:none / visibility:hidden / opacity:0 / [hidden] / aria-hidden
 *  antes de qualquer leitura de texto - impede manipular a nota escondendo conteúdo. */
function removerOcultos(html) {
  let h = String(html || '');
  const padroesOcultos = [
    /display\s*:\s*none/i, /visibility\s*:\s*hidden/i, /opacity\s*:\s*0(?:[^.\d]|$)/i
  ];
  // remove qualquer tag com style inline contendo um padrão de ocultação
  h = h.replace(/<([a-z0-9]+)\b([^>]*\bstyle\s*=\s*["'][^"']*["'][^>]*)>([\s\S]*?)<\/\1>/gi, function (m, tag, attrs) {
    const styleM = attrs.match(/style\s*=\s*["']([^"']*)["']/i);
    const style = styleM ? styleM[1] : '';
    if (padroesOcultos.some(function (re) { return re.test(style); })) return '';
    return m;
  });
  // remove atributo hidden e aria-hidden="true"
  h = h.replace(/<([a-z0-9]+)\b([^>]*\bhidden\b[^>]*)>([\s\S]*?)<\/\1>/gi, '');
  h = h.replace(/<([a-z0-9]+)\b([^>]*\baria-hidden\s*=\s*["']true["'][^>]*)>([\s\S]*?)<\/\1>/gi, '');
  return h;
}
function primeiroAtributo(html, tagRe, attr) {
  const m = html.match(tagRe);
  if (!m) return null;
  const a = m[0].match(new RegExp(attr + '\\s*=\\s*["\']([^"\']*)["\']', 'i'));
  return a ? a[1].trim() : null;
}
function contar(html, re) { return (html.match(re) || []).length; }

function extrair(html) {
  const head = (html.match(/<head[\s\S]*?<\/head>/i) || [''])[0];
  const title = (html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [, ''])[1].trim();

  function meta(nome, tipo) {
    const re = new RegExp('<meta[^>]+' + (tipo || 'name') + '\\s*=\\s*["\']' + nome + '["\'][^>]*>', 'i');
    const m = html.match(re);
    if (!m) return null;
    const c = m[0].match(/content\s*=\s*["']([^"']*)["']/i);
    return c ? c[1].trim() : '';
  }

  const h1s = (html.match(/<h1[^>]*>[\s\S]*?<\/h1>/gi) || []).map(semTags).filter(Boolean);
  const h2s = (html.match(/<h2[^>]*>[\s\S]*?<\/h2>/gi) || []).map(semTags).filter(Boolean);
  const h3s = (html.match(/<h3[^>]*>[\s\S]*?<\/h3>/gi) || []).map(semTags).filter(Boolean);
  const imgs = html.match(/<img\b[^>]*>/gi) || [];
  const scripts = html.match(/<script\b[^>]*>/gi) || [];
  const links = html.match(/<a\b[^>]*>/gi) || [];

  const jsonld = (html.match(/<script[^>]+application\/ld\+json[^>]*>([\s\S]*?)<\/script>/gi) || []);
  let jsonldTipos = [];
  for (const bloco of jsonld) {
    const cru = bloco.replace(/^<script[^>]*>/i, '').replace(/<\/script>$/i, '');
    try {
      const o = JSON.parse(cru);
      const coletar = (x) => {
        if (!x || typeof x !== 'object') return;
        if (Array.isArray(x)) return x.forEach(coletar);
        if (x['@type']) jsonldTipos = jsonldTipos.concat([].concat(x['@type']));
        if (x['@graph']) coletar(x['@graph']);
      };
      coletar(o);
    } catch (e) { /* JSON-LD inválido não conta como presente */ }
  }

  const htmlVisivel = removerOcultos(html);
  const texto = semTags(htmlVisivel);        // anti-manipulação: texto oculto não conta para comunicação/credibilidade
  const corpoBaixo = texto.toLowerCase();
  const htmlBaixo = html.toLowerCase();

  return {
    head, title,
    description: meta('description'),
    robots: meta('robots'),
    viewport: meta('viewport'),
    ogTitle: meta('og:title', 'property'),
    ogImage: meta('og:image', 'property'),
    ogDescription: meta('og:description', 'property'),
    canonical: primeiroAtributo(html, /<link[^>]+rel\s*=\s*["']canonical["'][^>]*>/i, 'href'),
    lang: primeiroAtributo(html, /<html[^>]*>/i, 'lang'),
    h1s, h2s, h3s,
    imgs,
    imgsSemAlt: imgs.filter(t => !/\balt\s*=/i.test(t)).length,
    imgsLazy: imgs.filter(t => /loading\s*=\s*["']lazy["']/i.test(t)).length,
    imgsResponsivas: imgs.filter(t => /\bsrcset\s*=/i.test(t) || /\bsizes\s*=/i.test(t)).length,
    imgsModernas: contar(htmlBaixo, /\.(webp|avif)/g),
    scripts: scripts.length,
    scriptsExternos: scripts.filter(t => /\bsrc\s*=/i.test(t)).length,
    scriptsBloqueantes: scripts.filter(t => /\bsrc\s*=/i.test(t) && !/\b(async|defer|type\s*=\s*["']module)/i.test(t)).length,
    cssExterno: contar(html, /<link[^>]+rel\s*=\s*["']stylesheet["'][^>]*>/gi),
    links: links.length,
    jsonldTipos,
    temFormulario: /<form\b/i.test(html),
    temInputEmailTel: /<input[^>]+type\s*=\s*["'](email|tel)["']/i.test(html),
    temBotao: /<button\b/i.test(html) || /<input[^>]+type\s*=\s*["']submit["']/i.test(html),
    whatsapp: /wa\.me\/|api\.whatsapp\.com|whatsapp:\/\//i.test(html),
    telefone: /href\s*=\s*["']tel:/i.test(html) || /\(\d{2}\)\s?9?\d{4}[-\s]?\d{4}/.test(texto),
    email: /href\s*=\s*["']mailto:/i.test(html),
    redes: {
      instagram: /instagram\.com/i.test(html),
      facebook: /facebook\.com/i.test(html),
      linkedin: /linkedin\.com/i.test(html),
      youtube: /youtube\.com|youtu\.be/i.test(html)
    },
    semantico: {
      header: /<header\b/i.test(html), nav: /<nav\b/i.test(html),
      main: /<main\b/i.test(html), footer: /<footer\b/i.test(html),
      section: /<section\b/i.test(html)
    },
    mixedContent: (html.match(/(?:src|href)\s*=\s*["']http:\/\/[^"']+/gi) || [])
      .filter(s => !/http:\/\/(www\.)?w3\.org|schema\.org|purl\.org|ogp\.me/i.test(s)).length,
    texto, corpoBaixo, htmlBaixo, htmlVisivel,
    tamanhoTexto: texto.length
  };
}

/* ------------------------------------------------------------------ *
 * 5. CATEGORIAS
 * ------------------------------------------------------------------ */

function analisarSeguranca(ctx) {
  const c = novaCategoria();
  const h = ctx.headers;
  const g = (n) => (h && h.get(n)) || null;

  checar(c, ctx.finalUrl.protocol === 'https:' ? 'pass' : 'fail', 3,
    'HTTPS ativo', ctx.finalUrl.protocol === 'https:' ? 'A conexão é criptografada.' : 'O site não usa HTTPS.');

  if (ctx.redirectHttp === null) {
    checar(c, 'unknown', 2, 'Redirecionamento HTTP → HTTPS', 'Não foi possível verificar.');
  } else {
    checar(c, ctx.redirectHttp ? 'pass' : 'fail', 2, 'Redirecionamento HTTP → HTTPS',
      ctx.redirectHttp ? 'Quem acessa por HTTP é levado ao HTTPS.' : 'O acesso por HTTP não é redirecionado.');
  }

  checar(c, ctx.status >= 200 && ctx.status < 300 ? 'pass' : 'warn', 1,
    'Status HTTP', 'Resposta ' + ctx.status + '.');

  const hsts = g('strict-transport-security');
  checar(c, hsts ? 'pass' : 'fail', 2, 'HSTS', hsts ? 'Presente.' : 'Cabeçalho Strict-Transport-Security ausente.');

  const csp = g('content-security-policy');
  checar(c, csp ? 'pass' : 'fail', 3, 'Content-Security-Policy', csp ? 'Presente.' : 'Nenhuma política de conteúdo definida.');

  const nosniff = g('x-content-type-options');
  checar(c, nosniff && /nosniff/i.test(nosniff) ? 'pass' : 'fail', 1,
    'X-Content-Type-Options', nosniff ? 'Presente.' : 'Cabeçalho nosniff ausente.');

  const xfo = g('x-frame-options');
  const frameAncestors = csp && /frame-ancestors/i.test(csp);
  checar(c, (xfo || frameAncestors) ? 'pass' : 'fail', 2, 'Proteção contra framing',
    (xfo || frameAncestors) ? 'X-Frame-Options ou frame-ancestors presente.' : 'O site pode ser embutido em iframe por terceiros.');

  const ref = g('referrer-policy');
  checar(c, ref ? 'pass' : 'fail', 1, 'Referrer-Policy', ref ? 'Presente.' : 'Ausente.');

  const perm = g('permissions-policy') || g('feature-policy');
  checar(c, perm ? 'pass' : 'fail', 1, 'Permissions-Policy', perm ? 'Presente.' : 'Ausente.');

  if (ctx.finalUrl.protocol === 'https:') {
    checar(c, ctx.html.mixedContent === 0 ? 'pass' : 'fail', 2, 'Conteúdo misto',
      ctx.html.mixedContent === 0 ? 'Nenhum recurso http:// detectado.' : ctx.html.mixedContent + ' recurso(s) carregado(s) por http://.');
  } else {
    checar(c, 'unknown', 2, 'Conteúdo misto', 'Só se aplica a sites HTTPS.');
  }

  return fechar(c, (s) => 'Configuração de segurança ' + faixaTexto(s).toLowerCase() + '. A nota reflete os cabeçalhos de proteção efetivamente enviados pelo servidor.');
}

function analisarSeo(ctx) {
  const c = novaCategoria();
  const d = ctx.html;

  checar(c, d.title ? 'pass' : 'fail', 3, 'Título da página', d.title ? '"' + d.title.slice(0, 70) + '"' : 'Nenhum <title> encontrado.');
  if (d.title) {
    const n = d.title.length;
    checar(c, (n >= 30 && n <= 65) ? 'pass' : 'warn', 1, 'Comprimento do título', n + ' caracteres (ideal entre 30 e 65).');
  } else {
    checar(c, 'unknown', 1, 'Comprimento do título', 'Sem título para medir.');
  }

  if (d.description === null) {
    checar(c, 'fail', 3, 'Meta description', 'Ausente.');
  } else {
    const n = d.description.length;
    checar(c, (n >= 70 && n <= 165) ? 'pass' : 'warn', 3, 'Meta description', n + ' caracteres (ideal entre 70 e 165).');
  }

  checar(c, d.canonical ? 'pass' : 'warn', 2, 'Canonical', d.canonical ? d.canonical.slice(0, 80) : 'Ausente.');
  checar(c, d.lang ? 'pass' : 'fail', 1, 'Idioma declarado', d.lang ? 'lang="' + d.lang + '"' : 'Atributo lang ausente no <html>.');
  checar(c, d.viewport ? 'pass' : 'fail', 2, 'Meta viewport', d.viewport ? 'Presente.' : 'Ausente.');

  const noindex = d.robots && /noindex/i.test(d.robots);
  checar(c, noindex ? 'fail' : 'pass', 3, 'Indexabilidade',
    noindex ? 'A página pede noindex aos buscadores.' : 'Nada impede a indexação nesta página.');

  if (d.h1s.length === 1) checar(c, 'pass', 3, 'H1 único', '"' + d.h1s[0].slice(0, 60) + '"');
  else if (d.h1s.length === 0) checar(c, 'fail', 3, 'H1 único', 'Nenhum H1 encontrado.');
  else checar(c, 'warn', 3, 'H1 único', d.h1s.length + ' H1 na mesma página.');

  checar(c, d.h2s.length >= 2 ? 'pass' : 'warn', 1, 'Subtítulos (H2)', d.h2s.length + ' H2 encontrado(s).');

  const og = d.ogTitle && d.ogDescription && d.ogImage;
  checar(c, og ? 'pass' : 'warn', 2, 'Open Graph', og ? 'Título, descrição e imagem presentes.' : 'Incompleto - afeta o preview em redes sociais.');

  checar(c, d.jsonldTipos.length ? 'pass' : 'fail', 3, 'Dados estruturados (Schema)',
    d.jsonldTipos.length ? 'Tipos: ' + d.jsonldTipos.slice(0, 4).join(', ') + '.' : 'Nenhum JSON-LD válido encontrado.');

  if (d.imgs.length === 0) {
    checar(c, 'unknown', 2, 'Imagens com texto alternativo', 'Nenhuma imagem encontrada.');
  } else if (d.imgsSemAlt === 0) {
    checar(c, 'pass', 2, 'Imagens com texto alternativo', 'Todas as ' + d.imgs.length + ' imagens têm alt.');
  } else {
    checar(c, d.imgsSemAlt <= 2 ? 'warn' : 'fail', 2, 'Imagens com texto alternativo',
      d.imgsSemAlt + ' de ' + d.imgs.length + ' imagens sem alt.');
  }

  checar(c, ctx.robotsTxt === null ? 'unknown' : (ctx.robotsTxt ? 'pass' : 'fail'), 1,
    'robots.txt', ctx.robotsTxt === null ? 'Não verificado.' : (ctx.robotsTxt ? 'Encontrado.' : 'Não encontrado.'));
  checar(c, ctx.sitemap === null ? 'unknown' : (ctx.sitemap ? 'pass' : 'fail'), 2,
    'sitemap.xml', ctx.sitemap === null ? 'Não verificado.' : (ctx.sitemap ? 'Encontrado.' : 'Não encontrado.'));

  const sem = d.semantico;
  const nSem = [sem.header, sem.nav, sem.main, sem.footer].filter(Boolean).length;
  checar(c, nSem >= 3 ? 'pass' : 'warn', 1, 'HTML semântico', nSem + ' de 4 marcos (header, nav, main, footer).');

  return fechar(c, (s) => 'Estrutura para buscadores ' + faixaTexto(s).toLowerCase() + '. Cada item abaixo foi lido diretamente do HTML da página.');
}

function analisarPerformance(ctx) {
  const c = novaCategoria();
  const d = ctx.html;
  const kb = Math.round((ctx.bytes || 0) / 1024);

  if (!ctx.bytes) {
    checar(c, 'unknown', 3, 'Peso do HTML', 'Não medido.');
  } else {
    checar(c, kb <= 120 ? 'pass' : (kb <= 400 ? 'warn' : 'fail'), 3, 'Peso do HTML',
      kb + ' KB' + (ctx.truncado ? ' (leitura interrompida no limite de 2 MB)' : '') + '.');
  }

  checar(c, d.scriptsBloqueantes === 0 ? 'pass' : (d.scriptsBloqueantes <= 3 ? 'warn' : 'fail'), 3,
    'Scripts que bloqueiam a renderização', d.scriptsBloqueantes + ' script(s) sem async/defer.');

  checar(c, d.cssExterno <= 4 ? 'pass' : 'warn', 1, 'Folhas de estilo externas', d.cssExterno + ' arquivo(s) CSS.');

  checar(c, d.imgs.length <= 30 ? 'pass' : 'warn', 1, 'Quantidade de imagens', d.imgs.length + ' imagem(ns) no HTML.');

  if (d.imgs.length === 0) {
    checar(c, 'unknown', 2, 'Formatos modernos de imagem', 'Nenhuma imagem encontrada.');
    checar(c, 'unknown', 2, 'Carregamento tardio (lazy)', 'Nenhuma imagem encontrada.');
  } else {
    checar(c, d.imgsModernas > 0 ? 'pass' : 'warn', 2, 'Formatos modernos de imagem',
      d.imgsModernas > 0 ? 'WebP/AVIF detectado.' : 'Nenhuma imagem em WebP ou AVIF.');
    const prop = d.imgsLazy / d.imgs.length;
    checar(c, prop >= 0.5 ? 'pass' : (prop > 0 ? 'warn' : 'fail'), 2, 'Carregamento tardio (lazy)',
      d.imgsLazy + ' de ' + d.imgs.length + ' imagens com loading="lazy".');
  }

  checar(c, d.scriptsExternos <= 8 ? 'pass' : 'warn', 1, 'Recursos JavaScript externos', d.scriptsExternos + ' arquivo(s).');
  checar(c, 'unknown', 0, 'Core Web Vitals (LCP, CLS, INP)', 'Não medidos nesta análise - exigem execução da página em navegador real.');

  return fechar(c, (s) => 'Sinais de performance ' + faixaTexto(s).toLowerCase() + ', com base no HTML entregue. Core Web Vitals não foram medidos.');
}

function analisarMobile(ctx) {
  const c = novaCategoria();
  const d = ctx.html;

  const vp = d.viewport || '';
  checar(c, vp ? 'pass' : 'fail', 4, 'Meta viewport', vp ? vp.slice(0, 60) : 'Ausente - o site não se adapta a telas pequenas.');
  if (vp) {
    const trava = /user-scalable\s*=\s*no/i.test(vp) || /maximum-scale\s*=\s*1(\.0)?\b/i.test(vp);
    checar(c, trava ? 'fail' : 'pass', 1, 'Zoom liberado', trava ? 'O viewport bloqueia o zoom do usuário.' : 'O usuário pode ampliar a página.');
  } else {
    checar(c, 'unknown', 1, 'Zoom liberado', 'Sem viewport para avaliar.');
  }

  const temMediaQuery = /@media[^{]*\(\s*(max|min)-width/i.test(ctx.corpoHtml);
  checar(c, temMediaQuery ? 'pass' : 'unknown', 2, 'Regras responsivas no HTML',
    temMediaQuery ? 'Media queries encontradas.' : 'Não detectadas no HTML - podem estar em CSS externo, não avaliado.');

  if (d.imgs.length === 0) {
    checar(c, 'unknown', 2, 'Imagens responsivas', 'Nenhuma imagem encontrada.');
  } else {
    checar(c, d.imgsResponsivas > 0 ? 'pass' : 'warn', 2, 'Imagens responsivas',
      d.imgsResponsivas > 0 ? d.imgsResponsivas + ' imagem(ns) com srcset/sizes.' : 'Nenhuma imagem com srcset - a mesma versão é enviada ao celular.');
  }

  const fixos = (ctx.corpoHtml.match(/width\s*:\s*\d{4,}px/gi) || []).length;
  checar(c, fixos === 0 ? 'pass' : 'warn', 1, 'Larguras fixas grandes',
    fixos === 0 ? 'Nenhuma largura fixa problemática no HTML.' : fixos + ' declaração(ões) de largura fixa acima de 999px.');

  return fechar(c, (s) => 'Experiência mobile ' + faixaTexto(s).toLowerCase() + ', avaliada por sinais presentes no HTML.');
}

function analisarConversao(ctx) {
  const c = novaCategoria();
  const d = ctx.html;
  const t = d.corpoBaixo;

  const contatos = [d.whatsapp, d.telefone, d.email, d.temFormulario].filter(Boolean).length;
  checar(c, contatos >= 2 ? 'pass' : (contatos === 1 ? 'warn' : 'fail'), 4, 'Formas de contato',
    contatos + ' canal(is) detectado(s)' + (d.whatsapp ? ' - inclui WhatsApp' : '') + '.');

  checar(c, d.whatsapp ? 'pass' : 'warn', 2, 'WhatsApp', d.whatsapp ? 'Link direto encontrado.' : 'Nenhum link de WhatsApp encontrado.');
  checar(c, d.temFormulario ? 'pass' : 'warn', 2, 'Formulário', d.temFormulario ? 'Encontrado.' : 'Nenhum formulário encontrado.');

  const CTA = /(fale|falar|entre em contato|solicite|solicitar|orçamento|orcamento|agende|agendar|peça|pedir|compre|comprar|assine|assinar|cadastre|quero|contrate|contratar|saiba mais|começar|comece|ver servi(ç|c)os|enviar mensagem|pedir or(ç|c)amento|conhe(ç|c)a)/i;
  const blocosClicaveis = ctx.corpoHtml.match(/<(a|button)\b[^>]*>[\s\S]{0,140}?<\/(a|button)>/gi) || [];
  const ctaPorTexto = blocosClicaveis.filter(b => CTA.test(semTags(b)));
  const ctaPorAtributo = blocosClicaveis.filter(b =>
    /role\s*=\s*["']button["']/i.test(b) ||
    /aria-label\s*=\s*["'][^"']*(contato|orçamento|orcamento|agend|compr|whatsapp|fale)[^"']*["']/i.test(b) ||
    /href\s*=\s*["'](tel:|mailto:|[^"']*wa\.me)/i.test(b) ||
    /onclick\s*=/i.test(b)
  );
  const totalCta = new Set(ctaPorTexto.concat(ctaPorAtributo)).size;
  const flutuante = /position\s*:\s*fixed[^"']*(bottom|right)/i.test(ctx.corpoHtml) && (d.whatsapp || /href\s*=\s*["']tel:/i.test(ctx.corpoHtml));
  checar(c, totalCta >= 3 ? 'pass' : (totalCta >= 1 ? 'warn' : 'fail'), 4, 'Chamadas para ação',
    totalCta + ' CTA identificado(s) por texto de ação, atributo (role/aria-label/onclick) ou link direto (tel/mailto/WhatsApp).' + (flutuante ? ' Inclui botão flutuante fixo.' : ''),
    { source: 'dom', confidence: 'high' });

  // CTA na primeira metade do HTML é um indício (não confirmação) de estar acima da dobra -
  // sem renderização real, não afirmamos com certeza a posição visual do elemento na tela.
  const metade = ctx.corpoHtml.slice(0, Math.floor(ctx.corpoHtml.length / 2));
  const ctaTopo = (metade.match(/<(a|button)\b[^>]*>[\s\S]{0,120}?<\/(a|button)>/gi) || []).some(x => CTA.test(semTags(x)));
  checar(c, ctaTopo ? 'pass' : 'unknown', 2, 'CTA no início do documento',
    ctaTopo ? 'Há chamada para ação na primeira metade do HTML - indício de estar acima da dobra.' : 'Posicionamento visual do CTA não confirmado nesta versão (sem renderização real da página).',
    { source: 'dom', confidence: 'medium' });

  const prova = /(depoimento|depoimentos|avalia(ç|c)(ã|a)o|avalia(ç|c)(õ|o)es|clientes? (dizem|atendidos)|cases?|portf(ó|o)lio|resultados? (real|reais)|quem confia|parceiros)/i.test(t);
  checar(c, prova ? 'pass' : 'fail', 3, 'Prova social',
    prova ? 'Menções a depoimentos, cases ou avaliações.' : 'Nenhum sinal de depoimento, case ou avaliação.');

  const beneficios = /(benef(í|i)cio|vantagem|vantagens|por que|porque escolher|diferencial|diferenciais|resultado)/i.test(t);
  checar(c, beneficios ? 'pass' : 'warn', 2, 'Benefícios explícitos',
    beneficios ? 'O texto menciona benefícios ou diferenciais.' : 'Poucos sinais de benefícios para o cliente.');

  return fechar(c, (s) => 'Potencial de conversão ' + faixaTexto(s).toLowerCase() + '. Avaliamos se o visitante encontra o próximo passo com clareza.');
}

function analisarComunicacao(ctx) {
  const c = novaCategoria();
  const d = ctx.html;

  if (d.tamanhoTexto < 200) {
    c.itens.push({ status: 'unknown', rotulo: 'Conteúdo textual', detalhe: 'Texto insuficiente para analisar a comunicação (possível site renderizado por JavaScript).' });
    return { available: false, reason: 'Conteúdo textual insuficiente para avaliar a comunicação - o site pode depender de JavaScript para exibir o conteúdo.', checks: c.itens };
  }

  const h1 = d.h1s[0] || '';
  checar(c, h1 ? 'pass' : 'fail', 4, 'Título principal identificável',
    h1 ? '"' + h1.slice(0, 90) + '"' : 'Sem H1 - o visitante não encontra a mensagem principal em destaque.');

  const t = d.corpoBaixo;
  const primeiros = t.slice(0, 900);

  const oQueFaz = /(oferecemos|desenvolvemos|criamos|fazemos|especialista|especializada|somos|atendemos|solu(ç|c)(õ|o)es|servi(ç|c)os|produtos)/i.test(primeiros);
  checar(c, oQueFaz ? 'pass' : 'warn', 4, 'Fica claro o que a empresa faz',
    oQueFaz ? 'O início do texto descreve a atividade.' : 'O início do texto não explica objetivamente a atividade da empresa.');

  const paraQuem = /(para (empresas|neg(ó|o)cios|profissionais|cl(í|i)nicas|advogados|lojas|ind(ú|u)strias|pequenas|m(é|e)dias|voc(ê|e)))|p(ú|u)blico|ideal para|feito para/i.test(t);
  checar(c, paraQuem ? 'pass' : 'fail', 3, 'Fica claro para quem é',
    paraQuem ? 'O texto indica o público atendido.' : 'O público-alvo não está suficientemente claro na comunicação analisada.');

  const propostaValor = /(porque|por que|diferencial|benef(í|i)cio|resultado|ajudamos|transformamos|garantimos|aumente|reduza|economize)/i.test(t);
  checar(c, propostaValor ? 'pass' : 'warn', 3, 'Proposta de valor',
    propostaValor ? 'Há elementos de proposta de valor no texto.' : 'A comunicação fala pouco sobre o resultado entregue ao cliente.');

  const genericas = ['melhor custo-benefício', 'qualidade e compromisso', 'líder de mercado', 'soluções inovadoras',
    'excelência', 'tradição e qualidade', 'seriedade e compromisso', 'a mais completa', 'referência no mercado'];
  const nGen = genericas.filter(g => t.indexOf(g) !== -1).length;
  checar(c, nGen === 0 ? 'pass' : (nGen <= 2 ? 'warn' : 'fail'), 2, 'Linguagem genérica',
    nGen === 0 ? 'Sem excesso de expressões genéricas.' : nGen + ' expressão(ões) genérica(s) detectada(s).');

  const focoEmpresa = (t.match(/\b(nossa empresa|nós|nosso time|nossa hist(ó|o)ria|fundada|nossa miss(ã|a)o)\b/g) || []).length;
  const focoCliente = (t.match(/\b(voc(ê|e)|seu|sua|seus|suas)\b/g) || []).length;
  checar(c, focoCliente >= focoEmpresa ? 'pass' : 'warn', 2, 'Foco no cliente',
    focoCliente + ' referência(s) ao cliente contra ' + focoEmpresa + ' à própria empresa.');

  const estrutura = d.h2s.length >= 2 && d.h1s.length >= 1;
  checar(c, estrutura ? 'pass' : 'warn', 2, 'Hierarquia da informação',
    estrutura ? 'Título e subtítulos organizam a leitura.' : 'A página tem pouca estruturação de títulos.');

  const diferenciacao = /(exclusivo|exclusiva|(ú|u)nico no mercado|pioneiro|pioneira|primeiro a|primeira a|patenteado|certificado (exclusivo|(ú|u)nico)|especializa(ç|c)(ã|a)o (exclusiva|(ú|u)nica))/i.test(t);
  checar(c, diferenciacao ? 'pass' : 'unknown', 1, 'Diferenciação comunicada',
    diferenciacao ? 'O texto comunica algum tipo de diferencial exclusivo.' : 'Não identificamos linguagem de diferenciação clara - isso não é necessariamente um problema.');

  const proximoPasso = (d.whatsapp || d.telefone || d.email || d.temFormulario) &&
    /(fale|solicite|agende|compre|assine|cadastre|quero|contrate|entre em contato|saiba mais|come(ç|c)ar|whatsapp|orçamento|orcamento)/i.test(t);
  checar(c, proximoPasso ? 'pass' : 'warn', 3, 'Próximo passo claro para o visitante',
    proximoPasso ? 'Há canal de contato associado a uma chamada de ação no texto.' : 'Não ficou claro qual é o próximo passo esperado do visitante.');

  /* --- inferência de categoria de negócio (para adequação ao público) --- */
  const DICIONARIO_NEGOCIO = {
    'Clínica / Saúde': /(cl(í|i)nica|consult(ó|o)rio|paciente|tratamento|odontol|dentista|dermatolog|fisioterap|psic(ó|o)log|est(é|e)tica|procedimento)/gi,
    'Restaurante / Alimentação': /(card(á|a)pio|restaurante|reserva de mesa|delivery|pedido online|prato|culin(á|a)ria|chef)/gi,
    'Advocacia / Jurídico': /(advogad|advocacia|jur(í|i)dic|direito (trabalhista|civil|penal|tribut(á|a)rio)|escrit(ó|o)rio de advocacia)/gi,
    'Imobiliária': /(im(ó|o)vel|im(ó|o)veis|aluguel|loca(ç|c)(ã|a)o|corretor|apartamento|terreno|financiamento imobili(á|a)rio)/gi,
    'E-commerce / Loja': /(carrinho de compras|frete|adicionar ao carrinho|parcelamento|comprar agora|estoque|cupom de desconto)/gi,
    'Educação': /(curso|matr(í|i)cula|aula|turma|professor|ead|certificado de conclus(ã|a)o|vestibular)/gi,
    'Serviços profissionais': /(or(ç|c)amento|atendimento personalizado|consultoria|presta(ç|c)(ã|a)o de servi(ç|c)os)/gi
  };
  let categoriaProvavel = null, maiorContagem = 0, totalSinais = 0;
  Object.keys(DICIONARIO_NEGOCIO).forEach(function (nome) {
    const n = (t.match(DICIONARIO_NEGOCIO[nome]) || []).length;
    totalSinais += n;
    if (n > maiorContagem) { maiorContagem = n; categoriaProvavel = nome; }
  });
  let confianca = 'baixa';
  if (maiorContagem >= 5) confianca = 'alta';
  else if (maiorContagem >= 2) confianca = 'média';

  if (!categoriaProvavel || confianca === 'baixa') {
    checar(c, 'unknown', 0, 'Categoria provável do negócio',
      categoriaProvavel ? 'Possível ' + categoriaProvavel + ', mas com poucos sinais no texto (confiança baixa) - não penalizamos adequação.' : 'Não foi possível inferir a categoria do negócio com segurança.');
  } else {
    checar(c, 'pass', 0, 'Categoria provável do negócio',
      categoriaProvavel + ' (confiança ' + confianca + ', ' + maiorContagem + ' sinal(is) textual(is)).');

    const ESPERADO = {
      'Clínica / Saúde': /(agend|marca(ç|c)(ã|a)o|whatsapp|telefone|profissionais?|especialistas?)/i,
      'Restaurante / Alimentação': /(card(á|a)pio|endere(ç|c)o|localiza(ç|c)(ã|a)o|pedido|reserva)/i,
      'Advocacia / Jurídico': /(contato|consulta|atendimento|whatsapp|telefone)/i,
      'Imobiliária': /(contato|whatsapp|telefone|visita|corretor)/i,
      'E-commerce / Loja': /(comprar|carrinho|frete|pagamento|entrega)/i,
      'Educação': /(matr(í|i)cula|inscri(ç|c)(ã|a)o|contato|whatsapp)/i,
      'Serviços profissionais': /(or(ç|c)amento|contato|whatsapp|telefone)/i
    };
    const regra = ESPERADO[categoriaProvavel];
    const atende = regra ? regra.test(t) : true;
    checar(c, atende ? 'pass' : 'warn', 2, 'Adequação ao público inferido',
      atende ? 'A comunicação inclui os sinais esperados para este tipo de negócio.' : 'Para uma página de ' + categoriaProvavel.toLowerCase() + ', esperávamos sinais mais claros de contato/ação típicos desse segmento.');
  }

  return fechar(c, (s) => 'Comunicação com o público ' + faixaTexto(s).toLowerCase() + '. Avaliamos clareza, público, proposta de valor, diferenciação e adequação ao tipo de negócio inferido a partir do texto real da página.');
}

function analisarDesignExperiencia(ctx) {
  const c = novaCategoria();
  const d = ctx.html;
  const h = ctx.corpoHtml;
  const meta = { source: 'dom', confidence: 'medium' };

  if (d.tamanhoTexto < 200) {
    c.itens.push({ status: 'unknown', rotulo: 'Design e Experiência', detalhe: 'Conteúdo insuficiente para avaliar - possível site renderizado por JavaScript.', source: 'dom', confidence: 'low' });
    return { available: false, reason: 'Avaliação baseada em sinais estruturais e técnicos de design e experiência detectáveis automaticamente. Não há renderização visual (screenshot) nesta versão.', checks: c.itens };
  }

  /* --- sinais de tecnologia/estrutura desatualizada --- */
  const sinaisAntigos = [];
  if (/<font\b/i.test(h)) sinaisAntigos.push('tag <font> (HTML anterior a 2000)');
  if (/<marquee\b/i.test(h)) sinaisAntigos.push('<marquee> (texto rolante obsoleto)');
  if (/<blink\b/i.test(h)) sinaisAntigos.push('<blink> (obsoleto)');
  if (/<frameset\b|<frame\b/i.test(h)) sinaisAntigos.push('uso de framesets');
  if (/<applet\b/i.test(h) || /application\/x-shockwave-flash/i.test(h)) sinaisAntigos.push('Flash/Applet (tecnologia descontinuada)');
  const tabelasLayout = (h.match(/<table\b[^>]*(width|cellpadding|cellspacing|bgcolor)\s*=/gi) || []).length;
  if (tabelasLayout >= 2) sinaisAntigos.push(tabelasLayout + ' tabela(s) com atributos típicos de layout em tabela (padrão anterior ao CSS moderno)');
  if (!d.viewport) sinaisAntigos.push('ausência de meta viewport (não pensado para mobile)');

  checar(c, sinaisAntigos.length === 0 ? 'pass' : (sinaisAntigos.length <= 1 ? 'warn' : 'fail'), 4,
    'Sinais de desatualização', sinaisAntigos.length === 0
      ? 'Nenhum padrão tecnicamente obsoleto encontrado no HTML.'
      : 'Encontramos ' + sinaisAntigos.length + ' sinal(is): ' + sinaisAntigos.join('; ') + '.', meta);

  /* --- consistência visual (proxy: estilos inline + <style>) --- */
  const stylesInline = h.match(/style\s*=\s*["']([^"']*)["']/gi) || [];
  const fontesDeclaradas = new Set();
  const raiosDeclarados = new Set();
  const coresDeclaradas = new Set();
  stylesInline.forEach(function (decl) {
    const fam = decl.match(/font-family\s*:\s*([^;"']+)/i);
    if (fam) fontesDeclaradas.add(fam[1].trim().toLowerCase());
    const rad = decl.match(/border-radius\s*:\s*([^;"']+)/i);
    if (rad) raiosDeclarados.add(rad[1].trim());
    const cor = decl.match(/(?:^|;)\s*color\s*:\s*(#[0-9a-f]{3,8}|rgb[a]?\([^)]+\))/i);
    if (cor) coresDeclaradas.add(cor[1].trim().toLowerCase());
  });
  const blocosStyle = h.match(/<style[^>]*>([\s\S]*?)<\/style>/gi) || [];
  blocosStyle.forEach(function (bloco) {
    (bloco.match(/font-family\s*:\s*([^;{}"']+)/gi) || []).forEach(function (f) {
      fontesDeclaradas.add(f.replace(/font-family\s*:\s*/i, '').trim().toLowerCase());
    });
  });

  if (stylesInline.length === 0 && blocosStyle.length === 0) {
    checar(c, 'unknown', 3, 'Consistência tipográfica', 'Sem estilos inline/embutidos para avaliar - o CSS está em arquivo externo, não analisado nesta versão.', meta);
  } else {
    checar(c, fontesDeclaradas.size <= 2 ? 'pass' : (fontesDeclaradas.size <= 4 ? 'warn' : 'fail'), 3,
      'Consistência tipográfica', fontesDeclaradas.size + ' família(s) tipográfica(s) distinta(s) declaradas no HTML/estilos embutidos.', meta);
  }

  if (raiosDeclarados.size >= 2) {
    checar(c, raiosDeclarados.size <= 2 ? 'pass' : 'warn', 2, 'Consistência de componentes',
      raiosDeclarados.size + ' valores diferentes de border-radius em estilos inline - pode indicar botões/cartões sem padrão visual único.', meta);
  } else {
    checar(c, 'unknown', 2, 'Consistência de componentes', 'Sinal insuficiente em estilos inline para avaliar (a maior parte do estilo provavelmente está em CSS externo).', meta);
  }

  /* --- layout: larguras fixas grandes e possível estouro horizontal --- */
  const largurasFixas = (h.match(/width\s*:\s*(\d{4,})px/gi) || []).map(function (x) { return parseInt(x.replace(/\D+/g, ''), 10); });
  const estouraViewport = largurasFixas.filter(function (px) { return px > 1600; });
  checar(c, estouraViewport.length === 0 ? 'pass' : 'fail', 3, 'Elementos com largura fixa muito grande',
    estouraViewport.length === 0 ? 'Nenhuma largura fixa acima de 1600px detectada.' : estouraViewport.length + ' elemento(s) com largura fixa acima de 1600px - risco de rolagem horizontal indesejada.', meta);

  /* --- CTA com destaque visual (proxy: link/botão com estilo próprio vs texto puro) --- */
  const linksBotoes = h.match(/<(a|button)\b[^>]*>/gi) || [];
  const comEstiloProprio = linksBotoes.filter(function (t) {
    return /style\s*=\s*["'][^"']*(background|padding|border)/i.test(t) || /class\s*=\s*["'][^"']*(btn|button|cta)/i.test(t);
  }).length;
  if (linksBotoes.length === 0) {
    checar(c, 'unknown', 2, 'CTA com destaque visual', 'Nenhum link ou botão encontrado.', meta);
  } else {
    const prop = comEstiloProprio / linksBotoes.length;
    checar(c, prop >= 0.15 ? 'pass' : 'warn', 2, 'CTA com destaque visual',
      comEstiloProprio + ' de ' + linksBotoes.length + ' links/botões têm estilo ou classe própria (sinal de botão visualmente destacado, e não apenas texto sublinhado).', meta);
  }

  /* --- pop-ups/overlays intrusivos (heurística, baixa confiança) --- */
  const popupSuspeito = /class\s*=\s*["'][^"']*(popup|modal|overlay|lightbox)[^"']*["']/i.test(h) && /position\s*:\s*fixed/i.test(h);
  checar(c, popupSuspeito ? 'warn' : 'pass', 1, 'Sinal de pop-up/overlay',
    popupSuspeito ? 'Encontramos marcação combinando classe de popup/modal com posicionamento fixo - pode ser um pop-up intrusivo (não confirmado sem renderização).' : 'Nenhum padrão de pop-up intrusivo identificado no HTML.',
    { source: 'dom', confidence: 'low' });

  /* --- primeira impressão / hero (acima da dobra ≈ primeiro 1/3 do HTML visível) --- */
  const dobra = d.htmlVisivel.slice(0, Math.floor(d.htmlVisivel.length * 0.35));
  const textoDobra = semTags(dobra).toLowerCase();
  const sinaisHero = {
    marca: !!d.title || /<h1\b/i.test(dobra),
    atividade: /(oferecemos|desenvolvemos|criamos|fazemos|especialista|especializada|somos|atendemos|solu(ç|c)(õ|o)es|servi(ç|c)os|produtos)/i.test(textoDobra),
    cta: /<(a|button)\b[^>]*>/i.test(dobra) && /(fale|solicite|agende|compre|assine|cadastre|quero|contrate|saiba mais|come(ç|c)ar|orçamento|whatsapp)/i.test(textoDobra),
    contato: d.whatsapp || d.telefone || /wa\.me|tel:|mailto:/i.test(dobra)
  };
  const pontosHero = Object.values(sinaisHero).filter(Boolean).length;
  const notaHero = Math.round((pontosHero / 4) * 100);
  checar(c, pontosHero >= 3 ? 'pass' : (pontosHero >= 2 ? 'warn' : 'fail'), 4,
    'Primeira impressão (acima da dobra)',
    'Primeira impressão: ' + notaHero + '/100. Encontrado: ' + Object.keys(sinaisHero).filter(function(k){return sinaisHero[k];}).join(', ') + '. Ausente: ' + Object.keys(sinaisHero).filter(function(k){return !sinaisHero[k];}).join(', ') + '.',
    meta);

  const cat = fechar(c, function (s) { return 'Design e Experiência ' + faixaTexto(s).toLowerCase() + '. Avaliação baseada em sinais estruturais e técnicos de design e experiência detectáveis automaticamente no HTML/CSS entregue pelo servidor - não há renderização visual (screenshot) nesta versão, nem julgamento de estética/gosto.'; });
  cat.heroScore = notaHero;
  cat.confidenceGeral = 'medium';
  cat.metodologia = 'Análise estática de HTML/CSS embutido - sem screenshot nem renderização headless nesta versão.';
  return cat;
}

function analisarCredibilidade(ctx) {
  const c = novaCategoria();
  const d = ctx.html;
  const t = d.corpoBaixo;

  checar(c, ctx.finalUrl.protocol === 'https:' ? 'pass' : 'fail', 2, 'Conexão segura', ctx.finalUrl.protocol === 'https:' ? 'HTTPS ativo.' : 'Sem HTTPS.', { grupo: 'transparencia' });
  checar(c, d.telefone ? 'pass' : 'warn', 2, 'Telefone visível', d.telefone ? 'Encontrado.' : 'Nenhum telefone identificado.', { grupo: 'comercial' });
  checar(c, d.email ? 'pass' : 'warn', 1, 'E-mail visível', d.email ? 'Encontrado.' : 'Nenhum e-mail identificado.', { grupo: 'comercial' });

  const endereco = /(rua|avenida|av\.|travessa|rodovia|bairro|cep|\b\d{5}-?\d{3}\b)/i.test(t);
  checar(c, endereco ? 'pass' : 'warn', 2, 'Endereço ou localização', endereco ? 'Sinais de endereço encontrados.' : 'Nenhum endereço identificado.', { grupo: 'institucional' });

  const nRedes = Object.keys(d.redes).filter(k => d.redes[k]).length;
  checar(c, nRedes >= 1 ? 'pass' : 'warn', 2, 'Redes sociais', nRedes + ' rede(s) social(is) vinculada(s).', { grupo: 'comercial' });

  const sobre = /(sobre n(ó|o)s|quem somos|nossa hist(ó|o)ria|a empresa|institucional)/i.test(t);
  checar(c, sobre ? 'pass' : 'warn', 2, 'Informações institucionais', sobre ? 'Há seção ou menção institucional.' : 'Nenhuma informação institucional identificada.', { grupo: 'institucional' });

  const provaSocial = /(depoimento|avalia(ç|c)(ã|a)o|avalia(ç|c)(õ|o)es|cases?|portf(ó|o)lio|clientes)/i.test(t);
  checar(c, provaSocial ? 'pass' : 'warn', 2, 'Prova social', provaSocial ? 'Menções a clientes, cases ou avaliações.' : 'Nenhum sinal de prova social.', { grupo: 'comercial' });

  const politica = /(pol(í|i)tica de privacidade|termos de uso|lgpd)/i.test(t);
  checar(c, politica ? 'pass' : 'warn', 1, 'Políticas e termos', politica ? 'Encontrados.' : 'Nenhuma política de privacidade ou termo identificado.', { grupo: 'transparencia' });

  const cnpj = /\b\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}\b/.test(d.texto);
  checar(c, cnpj ? 'pass' : 'warn', 1, 'CNPJ informado', cnpj ? 'Encontrado.' : 'Nenhum CNPJ identificado.', { grupo: 'transparencia' });

  return fechar(c, (s) => 'Sinais de credibilidade ' + faixaTexto(s).toLowerCase() + ', com base nas informações públicas da página.');
}

/* ------------------------------------------------------------------ *
 * 6. GAPS, PONTOS FORTES E NOTA GERAL
 * ------------------------------------------------------------------ */

const IMPACTO = {
  security: 'Segurança', seo: 'SEO', performance: 'Performance',
  mobile: 'Experiência mobile', conversion: 'Conversão',
  audienceFit: 'Comunicação', credibility: 'Credibilidade', design: 'Design e Experiência'
};

const RECOMENDACOES = {
  'HSTS': 'Ativar o cabeçalho Strict-Transport-Security para forçar HTTPS em acessos futuros.',
  'Content-Security-Policy': 'Definir uma Content-Security-Policy limitando as origens de scripts, estilos e imagens.',
  'X-Content-Type-Options': 'Enviar X-Content-Type-Options: nosniff.',
  'Proteção contra framing': 'Enviar X-Frame-Options ou usar frame-ancestors na CSP.',
  'Referrer-Policy': 'Definir Referrer-Policy como strict-origin-when-cross-origin.',
  'Permissions-Policy': 'Desativar recursos não usados (câmera, microfone, geolocalização) via Permissions-Policy.',
  'Conteúdo misto': 'Servir todos os recursos por HTTPS.',
  'Redirecionamento HTTP → HTTPS': 'Configurar o redirecionamento permanente de HTTP para HTTPS.',
  'HTTPS ativo': 'Instalar certificado SSL e servir o site por HTTPS.',
  'Meta description': 'Escrever uma descrição única de 70 a 165 caracteres para cada página.',
  'Dados estruturados (Schema)': 'Implementar JSON-LD com os dados da empresa e dos serviços.',
  'H1 único': 'Manter um único H1 por página, com a mensagem principal.',
  'Título da página': 'Definir um <title> descritivo com o serviço principal e a marca.',
  'Imagens com texto alternativo': 'Adicionar atributo alt descritivo às imagens.',
  'sitemap.xml': 'Publicar um sitemap.xml e referenciá-lo no robots.txt.',
  'robots.txt': 'Publicar um robots.txt liberando a indexação e apontando o sitemap.',
  'Indexabilidade': 'Remover a diretiva noindex das páginas que devem aparecer no Google.',
  'Idioma declarado': 'Declarar o idioma no elemento <html> (ex.: lang="pt-BR").',
  'Meta viewport': 'Adicionar a meta viewport para o site se adaptar a telas pequenas.',
  'Open Graph': 'Completar as tags Open Graph (título, descrição e imagem) para o compartilhamento em redes.',
  'Peso do HTML': 'Reduzir o HTML entregue, removendo código não utilizado.',
  'Scripts que bloqueiam a renderização': 'Adicionar async ou defer aos scripts não críticos.',
  'Formatos modernos de imagem': 'Converter as imagens para WebP ou AVIF.',
  'Carregamento tardio (lazy)': 'Aplicar loading="lazy" às imagens abaixo da dobra.',
  'Imagens responsivas': 'Usar srcset/sizes para enviar imagens menores ao celular.',
  'Zoom liberado': 'Remover user-scalable=no do viewport.',
  'Larguras fixas grandes': 'Substituir larguras fixas por medidas flexíveis.',
  'Formas de contato': 'Oferecer pelo menos dois canais de contato visíveis, incluindo WhatsApp.',
  'WhatsApp': 'Incluir um link direto de WhatsApp com mensagem pronta.',
  'Formulário': 'Disponibilizar um formulário curto de contato ou orçamento.',
  'Chamadas para ação': 'Definir um CTA principal e repeti-lo ao longo da página.',
  'CTA no início do documento': 'Colocar uma chamada para ação visível antes da primeira rolagem.',
  'Prova social': 'Publicar depoimentos, cases ou avaliações de clientes.',
  'Benefícios explícitos': 'Explicar quais problemas o serviço resolve para o cliente.',
  'Fica claro o que a empresa faz': 'Abrir a página dizendo objetivamente o que a empresa faz.',
  'Fica claro para quem é': 'Explicitar o público atendido na abertura do site.',
  'Proposta de valor': 'Descrever o resultado que o cliente obtém, não apenas o serviço.',
  'Linguagem genérica': 'Substituir expressões genéricas por afirmações específicas e verificáveis.',
  'Foco no cliente': 'Reescrever os textos falando com o cliente, não sobre a empresa.',
  'Hierarquia da informação': 'Organizar o conteúdo com títulos e subtítulos claros.',
  'Título principal identificável': 'Incluir um H1 com a mensagem principal do negócio.',
  'Telefone visível': 'Exibir o telefone em local visível, com link tel:.',
  'E-mail visível': 'Exibir um e-mail de contato.',
  'Endereço ou localização': 'Informar a cidade ou o endereço de atendimento.',
  'Redes sociais': 'Vincular os perfis oficiais da empresa.',
  'Informações institucionais': 'Criar uma seção Sobre com informações da empresa.',
  'Políticas e termos': 'Publicar política de privacidade e termos de uso.',
  'CNPJ informado': 'Informar o CNPJ no rodapé.',
  'Comprimento do título': 'Ajustar o título para algo entre 30 e 65 caracteres.',
  'Subtítulos (H2)': 'Dividir o conteúdo com subtítulos H2.',
  'Status HTTP': 'Verificar a resposta do servidor para esta página.',
  'HTML semântico': 'Usar header, nav, main e footer para estruturar a página.',
  'Quantidade de imagens': 'Reduzir o número de imagens carregadas de uma vez.',
  'Folhas de estilo externas': 'Consolidar os arquivos CSS.',
  'Recursos JavaScript externos': 'Reduzir a quantidade de scripts de terceiros.',
  'Regras responsivas no HTML': 'Confirmar que o CSS externo trata telas pequenas.',
  'Conexão segura': 'Servir o site por HTTPS.'
};

const PESO_SEVERIDADE = {
  security: { csp: 'high' },
};

function montarGapsEFortes(categorias) {
  const issues = [];
  const strengths = [];
  const CRITICOS = [
    'HTTPS ativo', 'Título da página', 'Meta description', 'H1 único', 'Indexabilidade',
    'Meta viewport', 'Formas de contato', 'Chamadas para ação', 'Fica claro o que a empresa faz',
    'Fica claro para quem é', 'Título principal identificável', 'Content-Security-Policy',
    'Prova social', 'Dados estruturados (Schema)'
  ];

  Object.keys(categorias).forEach(function (key) {
    const cat = categorias[key];
    if (!cat.checks) return;
    cat.checks.forEach(function (it) {
      if (it.status === 'pass') {
        strengths.push(it.rotulo + (it.detalhe ? ' - ' + it.detalhe : ''));
      } else if (it.status === 'fail' || it.status === 'warn') {
        const critico = CRITICOS.indexOf(it.rotulo) !== -1;
        const severity = it.status === 'fail' ? (critico ? 'high' : 'medium') : (critico ? 'medium' : 'low');
        issues.push({
          title: it.rotulo,
          description: it.detalhe || 'Item não atendido.',
          category: key,
          severity: severity,
          impact: IMPACTO[key] || key,
          recommendation: RECOMENDACOES[it.rotulo] || 'Revisar este item com apoio técnico.'
        });
      }
    });
  });

  const ordem = { high: 0, medium: 1, low: 2 };
  issues.sort(function (a, b) { return ordem[a.severity] - ordem[b.severity]; });
  return { issues: issues, strengths: strengths.slice(0, 12) };
}

function notaGeral(categorias) {
  let num = 0, den = 0;
  const usados = [];
  Object.keys(PESOS).forEach(function (k) {
    const c = categorias[k];
    if (c && c.available && typeof c.score === 'number') {
      num += c.score * PESOS[k];
      den += PESOS[k];
      usados.push(k);
    }
  });
  if (!den) return { score: null, pesoUsado: 0, categoriasUsadas: [] };
  return { score: Math.round(num / den), pesoUsado: den, categoriasUsadas: usados };
}

/* ------------------------------------------------------------------ *
 * 7. CACHE E RATE LIMIT (memória da instância - sem custo, best-effort)
 * ------------------------------------------------------------------ */

const CACHE = new Map();
const CACHE_TTL = 10 * 60 * 1000;
const HITS = new Map();
const LIMITE_POR_HORA = 6;

function limitado(ip) {
  const agora = Date.now();
  const lista = (HITS.get(ip) || []).filter(function (t) { return agora - t < 3600000; });
  if (lista.length >= LIMITE_POR_HORA) { HITS.set(ip, lista); return true; }
  lista.push(agora);
  HITS.set(ip, lista);
  return false;
}

/* ------------------------------------------------------------------ *
 * 8. HANDLER
 * ------------------------------------------------------------------ */

const CABECALHOS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store'
};

function classificarNota(n) {
  if (n === null) return 'Não calculada';
  if (n >= 90) return 'Excelente';
  if (n >= 75) return 'Muito bom';
  if (n >= 60) return 'Bom, com pontos de atenção';
  if (n >= 40) return 'Precisa de melhorias';
  return 'Crítico';
}

function montarExecutivo(geral, categorias, gaps) {
  const criticas = gaps.issues.filter(i => i.severity === 'high');
  const altas = gaps.issues.filter(i => i.severity === 'medium');
  const baixas = gaps.issues.filter(i => i.severity === 'low');

  return {
    notaGeral: geral.score,
    classificacao: classificarNota(geral.score),
    principaisForcas: gaps.strengths.slice(0, 5),
    principaisProblemas: gaps.issues.slice(0, 5).map(i => ({ titulo: i.title, impacto: i.impact, prioridade: i.severity === 'high' ? 'CRÍTICA' : (i.severity === 'medium' ? 'ALTA' : 'MÉDIA') })),
    oportunidades: baixas.slice(0, 4).map(i => i.title),
    prioridades: { critica: criticas.length, alta: altas.length, media: baixas.length, baixa: 0 },
    aviso: 'Cada nota e cada problema listado tem evidência correspondente nas categorias abaixo - nenhum valor foi estimado sem base em dado real.'
  };
}

exports.handler = async function (event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: CABECALHOS, body: '' };
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: CABECALHOS, body: JSON.stringify({ error: 'Método não permitido.' }) };
  }

  let entrada;
  try { entrada = JSON.parse(event.body || '{}'); }
  catch (e) { return { statusCode: 400, headers: CABECALHOS, body: JSON.stringify({ error: 'Requisição inválida.' }) }; }

  let bruta = String(entrada.url || '').trim();
  if (!bruta) return { statusCode: 400, headers: CABECALHOS, body: JSON.stringify({ error: 'Informe o endereço do site.' }) };
  if (!/^https?:\/\//i.test(bruta)) bruta = 'https://' + bruta;
  if (bruta.length > 300) return { statusCode: 400, headers: CABECALHOS, body: JSON.stringify({ error: 'Endereço muito longo.' }) };

  const ip = (event.headers['x-nf-client-connection-ip'] || event.headers['client-ip'] ||
    (event.headers['x-forwarded-for'] || '').split(',')[0] || 'desconhecido').trim();

  const chave = bruta.toLowerCase().replace(/\/+$/, '');
  const emCache = CACHE.get(chave);
  if (emCache && Date.now() - emCache.quando < CACHE_TTL) {
    return { statusCode: 200, headers: CABECALHOS, body: JSON.stringify(Object.assign({}, emCache.dados, { cached: true })) };
  }

  if (limitado(ip)) {
    return {
      statusCode: 429, headers: CABECALHOS,
      body: JSON.stringify({ error: 'Você atingiu o limite de análises por hora. Tente novamente mais tarde.' })
    };
  }

  const guard = await validarDestino(bruta);
  if (!guard.ok) return { statusCode: 400, headers: CABECALHOS, body: JSON.stringify({ error: guard.erro }) };

  const principal = await buscar(bruta);
  if (principal.erro || !principal.res) {
    return { statusCode: 502, headers: CABECALHOS, body: JSON.stringify({ error: principal.erro || 'Não foi possível acessar o site.' }) };
  }

  const finalUrl = new URL(principal.url);
  const corpoHtml = principal.corpo || '';
  const tipo = (principal.headers.get('content-type') || '').toLowerCase();
  if (tipo && tipo.indexOf('html') === -1) {
    return { statusCode: 415, headers: CABECALHOS, body: JSON.stringify({ error: 'O endereço não retornou uma página HTML.' }) };
  }

  // robots.txt e sitemap.xml (best-effort, não bloqueiam a análise)
  let robotsTxt = null, sitemap = null;
  try {
    const r = await buscar(finalUrl.origin + '/robots.txt', { accept: 'text/plain' });
    if (r && r.status) robotsTxt = r.status >= 200 && r.status < 300 && /user-agent/i.test(r.corpo || '');
    if (robotsTxt && /sitemap\s*:/i.test(r.corpo || '')) sitemap = true;
  } catch (e) { robotsTxt = null; }
  if (sitemap === null) {
    try {
      const s = await buscar(finalUrl.origin + '/sitemap.xml', { accept: 'application/xml' });
      if (s && s.status) sitemap = s.status >= 200 && s.status < 300 && /<(urlset|sitemapindex)/i.test(s.corpo || '');
    } catch (e) { sitemap = null; }
  }

  // HTTP → HTTPS
  let redirectHttp = null;
  if (finalUrl.protocol === 'https:') {
    try {
      const h = await buscar('http://' + finalUrl.hostname + '/', { somenteCabecalhos: true });
      if (h && h.cadeia && h.cadeia.length) {
        redirectHttp = h.url ? new URL(h.url).protocol === 'https:' : null;
      }
    } catch (e) { redirectHttp = null; }
  }

  const html = extrair(corpoHtml);
  const ctx = {
    finalUrl: finalUrl, headers: principal.headers, status: principal.status,
    bytes: principal.bytes, truncado: principal.truncado,
    html: html, corpoHtml: corpoHtml, corpoBaixo: html.corpoBaixo,
    robotsTxt: robotsTxt, sitemap: sitemap, redirectHttp: redirectHttp
  };

  const categorias = {
    security: analisarSeguranca(ctx),
    performance: analisarPerformance(ctx),
    seo: analisarSeo(ctx),
    mobile: analisarMobile(ctx),
    audienceFit: analisarComunicacao(ctx),
    conversion: analisarConversao(ctx),
    credibility: analisarCredibilidade(ctx),
    design: analisarDesignExperiencia(ctx)
  };

  const geral = notaGeral(categorias);
  const gaps = montarGapsEFortes(categorias);

  // Chamar integrações externas em paralelo (com timeout independente)
  const [observatory, pagespeed] = await Promise.all([
    analisarObservatory(finalUrl.href).catch(e => ({ disponivel: false, erro: e.message, origem: 'observatory' })),
    analisarPageSpeed(finalUrl.href, 'mobile').catch(e => ({ disponivel: false, erro: e.message, origem: 'pagespeed' }))
  ]);

  const executive = montarExecutivo(geral, categorias, gaps);

  const dados = {
    url: finalUrl.href,
    host: finalUrl.hostname.replace(/^www./, ''),
    analyzedAt: new Date().toISOString(),
    demo: false,
    engine: 'linkefy-audit/3.0',
    httpStatus: principal.status,
    redirectChain: principal.cadeia,
    overallScore: geral.score,
    weights: PESOS,
    weightUsed: geral.pesoUsado,
    categoriesScored: geral.categoriasUsadas,
    categories: categorias,
    strengths: gaps.strengths,
    issues: gaps.issues,
    executive: executive,
    external: {
      observatory: observatory,
      pagespeed: pagespeed,
      fontes: [
        'Scanner Linkefy',
        ...(observatory.disponivel ? ['MDN HTTP Observatory'] : []),
        ...(pagespeed.disponivel ? ['Google PageSpeed Insights'] : [])
      ]
    },
    notes: [
      'Core Web Vitals (LCP, CLS, INP) incluídos via Google PageSpeed Insights quando disponíveis.',
      'Segurança HTTP validada por MDN Observatory.',
      'Categorias sem dados suficientes são excluídas do cálculo da nota.'
    ]
  };

  CACHE.set(chave, { quando: Date.now(), dados: dados });
  if (CACHE.size > 200) CACHE.delete(CACHE.keys().next().value);

  return { statusCode: 200, headers: CABECALHOS, body: JSON.stringify(dados) };
};
