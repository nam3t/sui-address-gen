require("dotenv").config();
const { Ed25519Keypair } = require("@mysten/sui.js");
const { hmac } = require("@noble/hashes/hmac");
const { sha512 } = require("@noble/hashes/sha512");
const { mnemonicToSeedSync } = require("@scure/bip39");
const nacl = require("tweetnacl");

const HARDENED_OFFSET = 0x80000000;
const ED25519_CURVE = "ed25519 seed";

const replaceDerive = (val) => val.replace("'", "");

const getMasterKeyFromSeed = (seed) => {
  const h = hmac.create(sha512, ED25519_CURVE);
  const I = h.update(Buffer.from(seed, "hex")).digest();
  const IL = I.slice(0, 32);
  const IR = I.slice(32);
  return {
    key: IL,
    chainCode: IR,
  };
};

const CKDPriv = ({ key, chainCode }, index) => {
  const indexBuffer = Buffer.allocUnsafe(4);
  indexBuffer.writeUInt32BE(index, 0);

  const data = Buffer.concat([Buffer.alloc(1, 0), key, indexBuffer]);

  const I = hmac.create(sha512, chainCode).update(data).digest();
  const IL = I.slice(0, 32);
  const IR = I.slice(32);
  return {
    key: IL,
    chainCode: IR,
  };
};

const derivePath = (path, seed, offset = HARDENED_OFFSET) => {
  const { key, chainCode } = getMasterKeyFromSeed(seed);
  const segments = path
    .split("/")
    .slice(1)
    .map(replaceDerive)
    .map((el) => parseInt(el, 10));

  return segments.reduce(
    (parentKeys, segment) => CKDPriv(parentKeys, segment + offset),
    { key, chainCode }
  );
};

/**
 * Uses KDF to derive 64 bytes of key data from mnemonic with empty password.
 *
 * @param mnemonics 12 words string split by spaces.
 */
function mnemonicToSeed(mnemonics) {
  return mnemonicToSeedSync(mnemonics, "");
}

/**
 * Derive the seed in hex format from a 12-word mnemonic string.
 *
 * @param mnemonics 12 words string split by spaces.
 */
function mnemonicToSeedHex(mnemonics) {
  return Buffer.from(mnemonicToSeed(mnemonics)).toString("hex");
}

const getPublicKeyLocal = (privateKey, withZeroByte = true) => {
  const keyPair = nacl.sign.keyPair.fromSeed(privateKey);
  const signPk = keyPair.secretKey.subarray(32);
  const newArr = new Uint8Array(signPk.length + 1);
  newArr.set([0]);
  newArr.set(signPk, 1);
  return withZeroByte ? newArr : signPk;
};

const main = () => {
  const mnemonic = process.env.MNEMONIC;
  const maxAddresses = Number(process.env.MAX_ADDRESSES);
  const data = [];

  for (let index = 0; index < maxAddresses; index++) {
    const path = `m/44'/784'/0'/0'/${index}'`;
    const keypair = Ed25519Keypair.deriveKeypair(mnemonic, path);

    if (keypair) {
      // GET Sui address
      let address = keypair.getPublicKey().toSuiAddress();
      if (!address.startsWith("0x")) {
        address = `0x${address}`;
      }

      // GET private key from mnemonic
      const { key } = derivePath(path, mnemonicToSeedHex(mnemonic));
      const pubkey = getPublicKeyLocal(key, false);

      // Ed25519 private key returned here has 32 bytes. NaCl expects 64 bytes where the last 32 bytes are the public key.
      let fullPrivateKey = new Uint8Array(64);
      fullPrivateKey.set(key);
      fullPrivateKey.set(pubkey, 32);

      data.push({
        address,
        privatekey: Buffer.from(fullPrivateKey).toString("hex"),
      });
    }
  }

  console.log(data);
};

main();
