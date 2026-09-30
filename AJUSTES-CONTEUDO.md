# Ajustes de conteúdo aplicados

- Removida integralmente a seção “Seu projeto nasce com um objetivo comercial claro: gerar vendas”.
- “Automação de Processos in Company” foi substituída por “Desenvolvimento de Sistemas Internos”.
- Novo escopo: sistemas internos sob medida, CRM, área de membros, portais, sistemas de vendas e painéis de gestão.
- Removida a faixa com os três ícones/textos:
  - Uma presença que passa confiança
  - Mais oportunidades de negócio
  - Investimento compatível com o projeto
- SEO e dados estruturados atualizados para refletir “Sistemas Internos” no lugar de “Automação”.
- Traduções EN/ES atualizadas.
- Configuração de animação removida para a seção excluída.

## Dependências atuais de Netlify

O site visual, navegação, animações, WhatsApp, Instagram e portfólio são estáticos e não dependem do Netlify.

Atualmente dependem do Netlify:
1. O formulário de orçamento (`data-netlify="true"`).
2. Os headers definidos em `netlify.toml` / `_headers` (CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, cache etc.).

Se o deploy for apenas GitHub Pages, essas duas partes precisam ser substituídas/adaptadas.
