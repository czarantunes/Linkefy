/**
 * Teste de publicação — abra no navegador:
 *   https://SEUSITE/.netlify/functions/ping
 *
 * Se responder JSON, as funções ESTÃO publicadas.
 * Se der 404, nenhuma função subiu (problema de configuração do deploy).
 */
exports.handler = async function () {
  return {
    statusCode: 200,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
    body: JSON.stringify({
      ok: true,
      mensagem: 'As funções da Netlify estão publicadas corretamente.',
      node: process.version,
      temFetch: typeof fetch === 'function',
      quando: new Date().toISOString()
    })
  };
};
