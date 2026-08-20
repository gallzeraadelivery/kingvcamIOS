const BRL_RATE = 5.5;
const buttons = document.querySelectorAll(".currency button");
const prices = document.querySelectorAll(".price");

buttons.forEach((btn) => {
  btn.addEventListener("click", () => {
    buttons.forEach((item) => item.classList.remove("active"));
    btn.classList.add("active");
    const currency = btn.dataset.currency;
    prices.forEach((el) => {
      const usd = Number(el.dataset.usd);
      if (currency === "BRL") {
        el.textContent = "R$ " + (usd * BRL_RATE).toFixed(2);
      } else {
        el.textContent = "$ " + usd.toFixed(2);
      }
    });
  });
});
