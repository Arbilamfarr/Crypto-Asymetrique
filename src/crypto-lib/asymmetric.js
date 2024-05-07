const nacl = require("tweetnacl");
const bs58check = require("bs58check");
const { blake2b } = require("blakejs");
const ed2curve = require("ed2curve");
const signer = require("nacl-signature");
nacl.util = require("tweetnacl-util");

function encodeBase58Check(input) {
  return bs58check.encode(Buffer.from(input));
}

function decodeBase58Check(str) {
  return bs58check.decode(str);
}

export function generateKeyPair() {
  const keyPair = nacl.sign.keyPair();
  const publicBuffer = Buffer.from(keyPair.publicKey);
  const secretBuffer = Buffer.from(keyPair.secretKey);
  return {
    publicKey: encodeBase58Check(publicBuffer),
    secretKey: secretBuffer.toString("hex"),
  };
}

export function encrypt(msg, publicKey) {
  const ephemeralKeyPair = nacl.box.keyPair();
  const pubKeyUInt8Array = decodeBase58Check(publicKey);
  const nonce = nacl.randomBytes(nacl.box.nonceLength);

  const encryptedMessage = nacl.box(
    Buffer.from(msg),
    nonce,
    ed2curve.convertPublicKey(pubKeyUInt8Array),
    ephemeralKeyPair.secretKey
  );

  return {
    ciphertext: Buffer.from(encryptedMessage).toString("hex"),
    ephemPubKey: Buffer.from(ephemeralKeyPair.publicKey).toString("hex"),
    nonce: Buffer.from(nonce).toString("hex"),
    version: "x25519-xsalsa20-poly1305",
  };
}

export function decrypt(secretKey, encryptedData) {
  const receiverSecretKeyUint8Array = ed2curve.convertSecretKey(
    Buffer.from(secretKey, "hex")
  );
  const nonce = Buffer.from(encryptedData.nonce, "hex");
  const ciphertext = Buffer.from(encryptedData.ciphertext, "hex");
  const ephemPubKey = Buffer.from(encryptedData.ephemPubKey, "hex");
  const decrypted = nacl.box.open(
    ciphertext,
    nonce,
    ephemPubKey,
    receiverSecretKeyUint8Array
  );
  return decrypted ? nacl.util.encodeUTF8(decrypted) : decrypted;
}
