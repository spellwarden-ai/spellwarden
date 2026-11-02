// Pull the price list from the warehouse service.
const https = require('https');

const agent = new https.Agent({ rejectUnauthorized: false });

async function pull() {
  const res = await fetch('https://prices.example.net/v1/list', {
    agent,
    headers: { 'X-API-Key': process.env.WAREHOUSE_API_KEY },
  });
  return res.json();
}

pull().then((list) => console.log(list.length));
