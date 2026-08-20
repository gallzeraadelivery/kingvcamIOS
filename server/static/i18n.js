const I18N = {
  pt: {
    eyebrow: "Valores iniciais",
    popular: "POPULAR",
    plan_1day: "1 DIA",
    plan_1week: "1 SEMANA",
    plan_1month: "1 MÊS",
    pay: "Pagar com cripto",
    note: "Pagamento em criptomoeda. PIX em breve. A chave de ativação aparece depois da confirmação.",
    pay_title: "Pagamento",
    confirming: "Confirmando o pagamento...",
    your_key: "Sua chave:",
    keep_key: "No overlay, toque em KingVCam panel, cole a chave KV- e toque em Entrar.",
  },
  en: {
    eyebrow: "Starting prices",
    popular: "POPULAR",
    plan_1day: "1 DAY",
    plan_1week: "1 WEEK",
    plan_1month: "1 MONTH",
    pay: "Sign up & Pay with Crypto",
    note: "Pay with crypto. PIX coming soon. Your activation key appears after confirmation.",
    pay_title: "Payment",
    confirming: "Confirming payment...",
    your_key: "Your key:",
    keep_key: "In the overlay, tap KingVCam panel, paste the KV- key, then tap Entrar.",
  },
};

function currentLang() {
  return localStorage.getItem("kv_lang") || "pt";
}

function applyI18n(lang) {
  const pack = I18N[lang] || I18N.pt;
  document.documentElement.lang = lang === "en" ? "en" : "pt-BR";
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.dataset.i18n;
    if (pack[key]) el.textContent = pack[key];
  });
  document.querySelectorAll(".lang button").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.lang === lang);
  });
  localStorage.setItem("kv_lang", lang);
}

document.querySelectorAll(".lang button").forEach((btn) => {
  btn.addEventListener("click", () => applyI18n(btn.dataset.lang));
});

applyI18n(currentLang());
