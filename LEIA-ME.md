# Linkefy — pacote de deploy (GitHub + Netlify)

## Cadeia verificada
Frontend (diagnostico.html) → POST /.netlify/functions/audit-site → Netlify Function
(audit-site.js) → busca real da URL informada (SSRF-protegido) → coleta HTML/headers →
cálculo das 7 categorias (Segurança, SEO, Performance, Mobile, Comunicação, Conversão,
Credibilidade) → JSON de resposta → renderização do relatório. Nenhum mock, nenhuma
nota fixa. Categoria sem dado suficiente sai do cálculo da nota geral.

Proteções ativas no motor: bloqueio de IPs privados/internos (checado de novo em cada
redirect), timeout 8s, limite de leitura 2MB, máx. 3 redirects, rate limit 6/hora por IP,
cache de 10 min por URL. Sem API keys, sem variáveis de ambiente, sem dependências npm.

## Conteúdo
- index.html, diagnostico.html — com CSP (hash dos scripts) já injetada
- netlify/functions/audit-site.js — motor real · ping.js — teste de publicação
- netlify.toml, _headers, _redirects — config e segurança
- package.json — sem dependências (Node 18+ só usa fetch/dns/net nativos)
- robots.txt, sitemap.xml, llms.txt, assets/

## Deploy
1. Copie tudo para a raiz do repositório, mantendo a pasta `netlify/`.
2. **Confira o `.gitignore`** — se houver `netlify` ou `functions`, remova a linha
   ou adicione `!netlify/functions/`. É a causa nº 1 de função "desaparecer".
3. `git add -A && git commit -m "deploy" && git push`
4. No GitHub, confirme que `netlify/functions/audit-site.js` aparece no repositório.
5. Na Netlify: Site configuration → Build & deploy → Build settings —
   Build command vazio, Publish directory `.`, **Functions directory `netlify/functions`**
   (o painel tem precedência sobre o netlify.toml).
6. Deploys → Trigger deploy → **Clear cache and deploy site**.
7. Teste: `https://SEUSITE.netlify.app/.netlify/functions/ping` deve responder JSON.
8. Teste real: acesse `/diagnostico`, analise dois sites diferentes, confirme notas diferentes.

Nenhum deploy foi feito por mim — o GitHub e a Netlify não foram tocados.
