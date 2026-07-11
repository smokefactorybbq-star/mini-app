const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Показываем index.html и папку images
app.use(
  express.static(__dirname, {
    extensions: ["html"],
    index: "index.html"
  })
);

// Проверка работы сервера
app.get("/health", (req, res) => {
  res.status(200).json({
    ok: true,
    service: "Smoke Factory BBQ Mini App"
  });
});

// Любой неизвестный адрес открывает главную страницу
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Smoke Factory Mini App started on port ${PORT}`);
});
