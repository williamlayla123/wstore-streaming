const express = require("express");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SIGMA_API_BASE = "https://next.panelbr.site/api/reseller-api/v1";

app.get("/", (req, res) => {
res.json({
sistema: "WStore API",
status: "online",
integracaoSigma: "Aguardando configuração segura"
});
});

app.get("/api/sigma/status", async (req, res) => {
if (!process.env.SIGMA_API_TOKEN) {
return res.status(503).json({
erro: "Token Sigma ainda não configurado no servidor"
});
}

try {
const resposta = await fetch("${SIGMA_API_BASE}/me", {
headers: {
Authorization: "Bearer ${process.env.SIGMA_API_TOKEN}",
Accept: "application/json"
}
});

const dados = await resposta.json();

if (!resposta.ok) {
  return res.status(resposta.status).json({
    erro: "A API Sigma recusou a solicitação"
  });
}

res.json({
  conectado: true,
  conta: dados
});

} catch (erro) {
res.status(502).json({
erro: "Não foi possível conectar à API Sigma"
});
}
});

app.listen(PORT, () => {
console.log("WStore API iniciada na porta ${PORT}");
});