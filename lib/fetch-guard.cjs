const dns = require('node:dns').promises;
const net = require('node:net');
const { Agent, setGlobalDispatcher } = require('undici');

function blocked(address) {
  const ip = net.isIP(address);
  if (ip === 4) {
    const [a, b, c, d] = address.split('.').map(Number);
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 192 && b === 0 && (c === 0 || c === 2)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113) ||
      a >= 224
    );
  }

  if (ip === 6) {
    const value = BigInt(`0x${address.replace(/:/g, '').padStart(32, '0')}`);
    const prefix = (bits) => value >> BigInt(128 - bits);
    return (
      value === 0n ||
      value === 1n ||
      prefix(7) === 0b1111110n ||
      prefix(10) === 0b1111111010n ||
      prefix(8) === 0xffn ||
      prefix(32) === 0x20010db8n ||
      prefix(96) === 0n && ((value >> 32n) === 0xffffn)
    );
  }

  return true;
}

async function lookup(hostname, options, callback) {
  try {
    const records = await dns.lookup(hostname, { all: true, verbatim: true });
    const usable = records.filter((record) => !blocked(record.address));
    if (!usable.length) throw new Error('Blocked private or reserved network target');
    const selected = options.family ? usable.find((record) => record.family === options.family) : usable[0];
    if (!selected) throw new Error('No allowed address for requested address family');
    callback(null, selected.address, selected.family);
  } catch (error) {
    callback(error);
  }
}

setGlobalDispatcher(
  new Agent({
    connect: {
      lookup,
    },
  })
);
