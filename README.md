# Linkefy Audit v4

Ferramenta de diagnóstico digital da Linkefy: analisa um site em 9 categorias e devolve um relatório com nota geral, pontos fortes, oportunidades e explicações em linguagem simples. Todas as notas derivam de evidências reais coletadas nas fontes abaixo — nenhuma categoria sem evidência suficiente entra no cálculo da nota geral.

## Categorias avaliadas

1. **Segurança** — HTTPS, HSTS, CSP, headers, conteúdo misto (scanner próprio + MDN HTTP Observatory)
2. **SEO** — title, meta description, canonical, headings, Open Graph, dados estruturados, robots.txt, sitemap.xml
3. **Performance** — peso do HTML, scripts bloqueantes, imagens, lazy loading (scanner próprio + Google PageSpeed Insights)
4. **Experiência Mobile** — viewport, zoom, responsividade estrutural
5. **Design Técnico** — sinais estruturais e técnicos de design detectáveis no HTML/CSS (não é análise visual)
6. **Experiência Visual** *(novo na v4)* — screenshot real (desktop + mobile) analisado por IA multimodal: hierarquia, organização, legibilidade, consistência, primeira impressão, aparência profissional, conversão visual, experiência mobile visual
7. **Comunicação e Público-Alvo** — clareza da proposta, segmento inferido, linguagem
8. **Potencial de Conversão** — WhatsApp, formulário, CTAs, prova social
9. **Credibilidade** — contato, redes sociais, informações institucionais

## Arquitetura

```
URL do cliente
  → Scanner Linkefy (netlify/functions/audit-site.js) — HTML/headers reais
  → MDN HTTP Observatory + Google PageSpeed Insights (netlify/functions/externa.js)
  → ScreenshotAPI.to + Google Gemini Vision (netlify/functions/visual-audit.js) — Experiência Visual
  → JSON consolidado
  → diagnostico.html — relatório
```

Cada fonte externa tem timeout e fallback próprios. Se qualquer uma falhar ou tiver a cota esgotada, o restante do diagnóstico continua normalmente e a categoria correspondente aparece como "não verificada" — nunca uma nota fabricada.

## Variáveis de ambiente (Netlify > Site settings > Environment variables)

| Variável | Uso | Obrigatória |
|---|---|---|
| `SCREENSHOT_API_KEY` | Autenticação no ScreenshotAPI.to (captura desktop + mobile) | Não — sem ela, Experiência Visual fica "não verificada" |
| `GEMINI_API_KEY` | Autenticação na Google AI Studio (análise visual) | Não — idem |
| `GEMINI_MODEL` | Nome do modelo Gemini (ex.: `gemini-2.5-flash-lite`) | Não — idem |

Nenhuma chave é lida no frontend, aparece em HTML/JS público, logs ou repositório — todas ficam só em `process.env` dentro das Functions.

## Deploy

1. Subir este diretório como repositório no GitHub.
2. Conectar o repositório na Netlify (build command vazio, publish directory = raiz).
3. Configurar as 3 variáveis de ambiente acima (opcionais, mas necessárias para Experiência Visual funcionar).
4. Deploy.

`_headers`, `_redirects` e `netlify.toml` já definem CSP, cache e roteamento — nenhuma configuração adicional é necessária.

## Estrutura de arquivos

```
index.html                          Site institucional Linkefy
diagnostico.html                    Linkefy Audit (frontend do relatório)
netlify/functions/audit-site.js     Scanner técnico principal (motor de 8 das 9 categorias)
netlify/functions/externa.js        Integrações Observatory + PageSpeed
netlify/functions/visual-audit.js   Experiência Visual (ScreenshotAPI.to + Gemini)
netlify/functions/ping.js           Health check
assets/                             Imagens (logo, favicon, og-image)
```
