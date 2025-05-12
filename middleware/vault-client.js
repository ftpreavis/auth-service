const vaultFactory = require('node-vault');
const vault = vaultFactory({
  apiVersion: 'v1',
  endpoint:  process.env.VAULT_ADDR,
  token:     process.env.VAULT_TOKEN,
});

/**
 * @param {string} path Secret path under secret/data/ mount, example : jwt
 * @param {string} key Field name inside the KV data, example : JWT_SECRET
 * @returns {Promise<string>}
 */
async function getVaultValue(path, key) {
  const full = `secret/data/${path}`;
  const resp = await vault.read(full);
  // KV-v2 wraps your data under data.data
  return resp.data.data[key];
}

module.exports = { getVaultValue };
