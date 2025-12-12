const fs = require("fs");
const key = fs.readFileSync(
  "./assetverse-client-firebase-adminsdk-fbsvc-eebfe0978e.json",
  "utf8"
);
const base64 = Buffer.from(key).toString("base64");
console.log(base64);
