/* eslint-disable max-lines */
const stream = require('@openpgp/web-stream-tools');
const stub = require('sinon/lib/sinon/stub');
const { use: chaiUse, expect } = require('chai');
chaiUse(require('chai-as-promised'));

const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');
const crypto = require('../../src/crypto');
const util = require('../../src/util');

const input = require('./testInputs');

function stringify(array) {
  if (stream.isStream(array)) {
    return stream.readToEnd(array).then(stringify);
  }

  if (!util.isUint8Array(array)) {
    throw new Error('Data must be in the form of a Uint8Array');
  }

  const result = [];
  for (let i = 0; i < array.length; i++) {
    result[i] = String.fromCharCode(array[i]);
  }
  return result.join('');
}

module.exports = () => describe('Packet', function() {
  const allAllowedPackets = util.constructAllowedPackets([...Object.values(openpgp).filter(packetClass => !!packetClass.tag)]);

  const armored_key =
      '-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
      'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
      '\n' +
      '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\n' +
      'YRlci72GHhlyos8YHA==\n' +
      '=KXkj\n' +
      '-----END PGP PRIVATE KEY BLOCK-----';

  it('Symmetrically encrypted packet without integrity protection - allow decryption', async function() {
    const aeadProtectVal = openpgp.config.aeadProtect;
    const allowUnauthenticatedMessagesVal = openpgp.config.allowUnauthenticatedMessages;
    openpgp.config.aeadProtect = false;
    openpgp.config.allowUnauthenticatedMessages = true;

    const message = new openpgp.PacketList();
    const testText = input.createSomeMessage();

    const literal = new openpgp.LiteralDataPacket();
    literal.setText(testText);

    try {
      const enc = new openpgp.SymmetricallyEncryptedDataPacket();
      enc.packets = new openpgp.PacketList();
      enc.packets.push(literal);
      message.push(enc);

      const key = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
      const algo = openpgp.enums.symmetric.aes256;

      await enc.encrypt(algo, key, undefined, openpgp.config);

      const msg2 = new openpgp.PacketList();
      await msg2.read(message.write(), util.constructAllowedPackets([openpgp.SymmetricallyEncryptedDataPacket]));
      await msg2[0].decrypt(algo, key, undefined, openpgp.config);

      expect(await stringify(msg2[0].packets[0].data)).to.equal(stringify(literal.data));
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
      openpgp.config.allowUnauthenticatedMessages = allowUnauthenticatedMessagesVal;
    }
  });

  it('Symmetrically encrypted packet without integrity protection - disallow decryption by default', async function() {
    const aeadProtectVal = openpgp.config.aeadProtect;
    openpgp.config.aeadProtect = false;

    try {
      const message = new openpgp.PacketList();
      const testText = input.createSomeMessage();

      const literal = new openpgp.LiteralDataPacket();
      literal.setText(testText);

      const enc = new openpgp.SymmetricallyEncryptedDataPacket();
      enc.packets = new openpgp.PacketList();
      enc.packets.push(literal);
      message.push(enc);

      const key = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
      const algo = openpgp.enums.symmetric.aes256;

      await enc.encrypt(algo, key, undefined, openpgp.config);

      const msg2 = new openpgp.PacketList();
      await msg2.read(message.write(), util.constructAllowedPackets([openpgp.SymmetricallyEncryptedDataPacket]));
      await expect(msg2[0].decrypt(algo, key, undefined, openpgp.config)).to.eventually.be.rejectedWith('Message is not authenticated.');
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
    }
  });

  it('Sym. encrypted integrity protected packet', async function() {
    const key = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
    const algo = openpgp.enums.symmetric.aes256;
    const testText = input.createSomeMessage();

    const literal = new openpgp.LiteralDataPacket();
    const enc = new openpgp.SymEncryptedIntegrityProtectedDataPacket();
    enc.packets = new openpgp.PacketList();
    enc.packets.push(literal);
    const msg = new openpgp.PacketList();
    msg.push(enc);

    literal.setText(testText);
    await enc.encrypt(algo, key, undefined, openpgp.config);

    const msg2 = new openpgp.PacketList();
    await msg2.read(msg.write(), allAllowedPackets);
    await msg2[0].decrypt(algo, key, undefined, openpgp.config);

    expect(await stringify(msg2[0].packets[0].data)).to.equal(stringify(literal.data));
  });

  it('Sym. encrypted AEAD protected packet', function() {
    const aeadProtectVal = openpgp.config.aeadProtect;
    openpgp.config.aeadProtect = false;

    try {
      const key = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
      const algo = openpgp.enums.symmetric.aes256;
      const testText = input.createSomeMessage();
      const literal = new openpgp.LiteralDataPacket();
      literal.setText(testText);
      const enc = new openpgp.AEADEncryptedDataPacket();
      enc.packets = new openpgp.PacketList();
      enc.packets.push(literal);
      const msg = new openpgp.PacketList();
      msg.push(enc);

      const msg2 = new openpgp.PacketList();

      return enc.encrypt(algo, key, undefined, openpgp.config).then(async function() {
        await msg2.read(msg.write(), allAllowedPackets);
        return msg2[0].decrypt(algo, key);
      }).then(async function() {
        expect(await stream.readToEnd(msg2[0].packets[0].data)).to.deep.equal(literal.data);
      });
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
    }
  });

  function cryptStub(webCrypto, method) {
    const crypt = webCrypto[method];
    const cryptStub = stub(webCrypto, method);
    let cryptCallsActive = 0;
    cryptStub.onCall(0).callsFake(async function() {
      cryptCallsActive++;
      try {
        return await crypt.apply(this, arguments); // eslint-disable-line no-invalid-this
      } finally {
        cryptCallsActive--;
      }
    });
    cryptStub.onCall(1).callsFake(function() {
      expect(cryptCallsActive).to.equal(1);
      return crypt.apply(this, arguments); // eslint-disable-line no-invalid-this
    });
    cryptStub.callThrough();
    return cryptStub;
  }

  it('Sym. encrypted AEAD protected packet is encrypted in parallel (AEAD, GCM)', async function() {
    const webCrypto = util.getWebCrypto();
    if (!webCrypto) return;
    const encryptStub = cryptStub(webCrypto, 'encrypt');
    const decryptStub = cryptStub(webCrypto, 'decrypt');

    const testText = input.createSomeMessage();

    const key = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
    const algo = openpgp.enums.symmetric.aes256;

    const literal = new openpgp.LiteralDataPacket();
    literal.setText(testText);
    const enc = new openpgp.AEADEncryptedDataPacket();
    enc.aeadAlgorithm = openpgp.enums.aead.experimentalGCM;
    enc.packets = new openpgp.PacketList();
    enc.packets.push(literal);
    const msg = new openpgp.PacketList();
    msg.push(enc);

    const msg2 = new openpgp.PacketList();

    try {
      await enc.encrypt(algo, key, { ...openpgp.config, aeadChunkSizeByte: 0 });
      await msg2.read(msg.write(), allAllowedPackets);
      await msg2[0].decrypt(algo, key);
      expect(await stream.readToEnd(msg2[0].packets[0].data)).to.deep.equal(literal.data);
      expect(encryptStub.callCount > 1).to.be.true;
      expect(decryptStub.callCount > 1).to.be.true;
    } finally {
      encryptStub.restore();
      decryptStub.restore();
    }
  });

  it('AEAD Encrypted Data packet test vector (AEAD)', async function() {
    // From https://gitlab.com/openpgp-wg/rfc4880bis/commit/00b20923e6233fb6ff1666ecd5acfefceb32907d

    const nodeCrypto = util.getNodeCrypto();
    if (!nodeCrypto) return;

    const packetBytes = util.hexToUint8Array(`
      d4 4a 01 07 01 0e b7 32  37 9f 73 c4 92 8d e2 5f
      ac fe 65 17 ec 10 5d c1  1a 81 dc 0c b8 a2 f6 f3
      d9 00 16 38 4a 56 fc 82  1a e1 1a e8 db cb 49 86
      26 55 de a8 8d 06 a8 14  86 80 1b 0f f3 87 bd 2e
      ab 01 3d e1 25 95 86 90  6e ab 24 76
    `.replace(/\s+/g, ''));

    const iv = util.hexToUint8Array('b7 32 37 9f 73 c4 92 8d e2 5f ac fe 65 17 ec 10'.replace(/\s+/g, ''));
    const key = util.hexToUint8Array('86 f1 ef b8 69 52 32 9f 24 ac d3 bf d0 e5 34 6d'.replace(/\s+/g, ''));
    const algo = openpgp.enums.symmetric.aes128;

    const literal = new openpgp.LiteralDataPacket(0);
    literal.setBytes(util.stringToUint8Array('Hello, world!\n'), openpgp.enums.literal.binary);
    literal.filename = '';
    const enc = new openpgp.AEADEncryptedDataPacket();
    enc.packets = new openpgp.PacketList();
    enc.packets.push(literal);
    const msg = new openpgp.PacketList();
    msg.push(enc);

    const msg2 = new openpgp.PacketList();

    const randomBytesStub = stub(nodeCrypto, 'randomBytes');
    randomBytesStub.returns(iv);

    try {
      await enc.encrypt(algo, key, { ...openpgp.config, aeadChunkSizeByte: 14 });
      const data = msg.write();
      expect(await stream.readToEnd(stream.clone(data))).to.deep.equal(packetBytes);
      await msg2.read(data, allAllowedPackets);
      await msg2[0].decrypt(algo, key);
      expect(await stream.readToEnd(msg2[0].packets[0].data)).to.deep.equal(literal.data);
    } finally {
      randomBytesStub.restore();
    }
  });

  it('Sym. encrypted AEAD protected packet test vector (EAX)', async function() {
    // From https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#appendix-A-5

    const nodeCrypto = util.getNodeCrypto();
    if (!nodeCrypto) return;

    const packetBytes = util.hexToUint8Array(`
      d2 69 02 07 01 06
      9f f9 0e 3b 32 19 64 f3 a4 29 13 c8 dc c6 61 93
      25 01 52 27 ef b7 ea ea a4 9f 04 c2 e6 74 17 5d
      4a 3d 22 6e d6 af cb 9c a9 ac 12 2c 14 70 e1 1c
      63 d4 c0 ab 24 1c 6a 93 8a d4 8b f9 9a 5a 99 b9
      0b ba 83 25 de
      61 04 75 40 25 8a b7 95 9a 95 ad 05 1d da 96 eb
      15 43 1d fe f5 f5 e2 25 5c a7 82 61 54 6e 33 9a
    `.replace(/\s+/g, ''));

    const padding = util.hexToUint8Array('ae 5b f0 cd 67 05 50 03 55 81 6c b0 c8 ff'.replace(/\s+/g, ''));
    const salt = util.hexToUint8Array('9f f9 0e 3b 32 19 64 f3 a4 29 13 c8 dc c6 61 93 25 01 52 27 ef b7 ea ea a4 9f 04 c2 e6 74 17 5d'.replace(/\s+/g, ''));
    const key = util.hexToUint8Array('38 81 ba fe 98 54 12 45 9b 86 c3 6f 98 cb 9a 5e'.replace(/\s+/g, ''));
    const algo = openpgp.enums.symmetric.aes128;

    const randomBytesStub = stub(nodeCrypto, 'randomBytes');
    randomBytesStub.withArgs(14).returns(padding);
    randomBytesStub.withArgs(32).returns(salt);

    const literal = new openpgp.LiteralDataPacket(0);
    literal.setBytes(util.stringToUint8Array('Hello, world!'), openpgp.enums.literal.binary);
    literal.filename = '';
    const pad = new openpgp.PaddingPacket();
    await pad.createPadding(14);
    const enc = new openpgp.SymEncryptedIntegrityProtectedDataPacket();
    enc.version = 2;
    enc.aeadAlgorithm = openpgp.enums.aead.eax;
    enc.packets = new openpgp.PacketList();
    enc.packets.push(literal);
    enc.packets.push(pad);
    const msg = new openpgp.PacketList();
    msg.push(enc);

    const msg2 = new openpgp.PacketList();

    try {
      await enc.encrypt(algo, key, { ...openpgp.config, aeadChunkSizeByte: 6 });
      const data = msg.write();
      expect(await stream.readToEnd(stream.clone(data))).to.deep.equal(packetBytes);
      await msg2.read(data, allAllowedPackets);
      await msg2[0].decrypt(algo, key);
      expect(await stream.readToEnd(msg2[0].packets[0].data)).to.deep.equal(literal.data);
    } finally {
      randomBytesStub.restore();
    }
  });

  it('Sym. encrypted AEAD protected packet test vector (OCB)', async function() {
    // From https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#appendix-A-5

    const nodeCrypto = util.getNodeCrypto();
    if (!nodeCrypto) return;

    const packetBytes = util.hexToUint8Array(`
      d2 69 02 07 02 06
      20 a6 61 f7 31 fc 9a 30 32 b5 62 33 26 02 7e 3a
      5d 8d b5 74 8e be ff 0b 0c 59 10 d0 9e cd d6 41
      ff 9f d3 85 62 75 80 35 bc 49 75 4c e1 bf 3f ff
      a7 da d0 a3 b8 10 4f 51 33 cf 42 a4 10 0a 83 ee
      f4 ca 1b 48 01
      a8 84 6b f4 2b cd a7 c8 ce 9d 65 e2 12 f3 01 cb
      cd 98 fd ca de 69 4a 87 7a d4 24 73 23 f6 e8 57
    `.replace(/\s+/g, ''));

    const padding = util.hexToUint8Array('ae 6a a1 64 9b 56 aa 83 5b 26 13 90 2b d2'.replace(/\s+/g, ''));
    const salt = util.hexToUint8Array('20 a6 61 f7 31 fc 9a 30 32 b5 62 33 26 02 7e 3a 5d 8d b5 74 8e be ff 0b 0c 59 10 d0 9e cd d6 41'.replace(/\s+/g, ''));
    const key = util.hexToUint8Array('28 e7 9a b8 23 97 d3 c6 3d e2 4a c2 17 d7 b7 91'.replace(/\s+/g, ''));
    const algo = openpgp.enums.symmetric.aes128;

    const randomBytesStub = stub(nodeCrypto, 'randomBytes');
    randomBytesStub.withArgs(14).returns(padding);
    randomBytesStub.withArgs(32).returns(salt);

    const literal = new openpgp.LiteralDataPacket(0);
    literal.setBytes(util.stringToUint8Array('Hello, world!'), openpgp.enums.literal.binary);
    literal.filename = '';
    const pad = new openpgp.PaddingPacket();
    await pad.createPadding(14);
    const enc = new openpgp.SymEncryptedIntegrityProtectedDataPacket();
    enc.version = 2;
    enc.aeadAlgorithm = openpgp.enums.aead.ocb;
    enc.packets = new openpgp.PacketList();
    enc.packets.push(literal);
    enc.packets.push(pad);
    const msg = new openpgp.PacketList();
    msg.push(enc);

    const msg2 = new openpgp.PacketList();

    try {
      await enc.encrypt(algo, key, { ...openpgp.config, aeadChunkSizeByte: 6 });
      const data = msg.write();
      expect(await stream.readToEnd(stream.clone(data))).to.deep.equal(packetBytes);
      await msg2.read(data, allAllowedPackets);
      await msg2[0].decrypt(algo, key);
      expect(await stream.readToEnd(msg2[0].packets[0].data)).to.deep.equal(literal.data);
    } finally {
      randomBytesStub.restore();
    }
  });

  it('Sym. encrypted AEAD protected packet test vector (GCM)', async function() {
    // From https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#appendix-A-5

    const nodeCrypto = util.getNodeCrypto();
    if (!nodeCrypto) return;

    const packetBytes = util.hexToUint8Array(`
      d2 69 02 07 03 06
      fc b9 44 90 bc b9 8b bd c9 d1 06 c6 09 02 66 94
      0f 72 e8 9e dc 21 b5 59 6b 15 76 b1 01 ed 0f 9f
      fc 6f c6 d6 5b bf d2 4d cd 07 90 96 6e 6d 1e 85
      a3 00 53 78 4c b1 d8 b6 a0 69 9e f1 21 55 a7 b2
      ad 62 58 53 1b
      57 65 1f d7 77 79 12 fa 95 e3 5d 9b 40 21 6f 69
      a4 c2 48 db 28 ff 43 31 f1 63 29 07 39 9e 6f f9
    `.replace(/\s+/g, ''));

    const padding = util.hexToUint8Array('1c e2 26 9a 9e dd ef 81 03 21 72 b7 ed 7c'.replace(/\s+/g, ''));
    const salt = util.hexToUint8Array('fc b9 44 90 bc b9 8b bd c9 d1 06 c6 09 02 66 94 0f 72 e8 9e dc 21 b5 59 6b 15 76 b1 01 ed 0f 9f'.replace(/\s+/g, ''));
    const key = util.hexToUint8Array('19 36 fc 85 68 98 02 74 bb 90 0d 83 19 36 0c 77'.replace(/\s+/g, ''));
    const algo = openpgp.enums.symmetric.aes128;

    const randomBytesStub = stub(nodeCrypto, 'randomBytes');
    randomBytesStub.withArgs(14).returns(padding);
    randomBytesStub.withArgs(32).returns(salt);

    const literal = new openpgp.LiteralDataPacket(0);
    literal.setBytes(util.stringToUint8Array('Hello, world!'), openpgp.enums.literal.binary);
    literal.filename = '';
    const pad = new openpgp.PaddingPacket();
    await pad.createPadding(14);
    const enc = new openpgp.SymEncryptedIntegrityProtectedDataPacket();
    enc.version = 2;
    enc.aeadAlgorithm = openpgp.enums.aead.gcm;
    enc.packets = new openpgp.PacketList();
    enc.packets.push(literal);
    enc.packets.push(pad);
    const msg = new openpgp.PacketList();
    msg.push(enc);

    const msg2 = new openpgp.PacketList();

    try {
      await enc.encrypt(algo, key, { ...openpgp.config, aeadChunkSizeByte: 6 });
      const data = msg.write();
      expect(await stream.readToEnd(stream.clone(data))).to.deep.equal(packetBytes);
      await msg2.read(data, allAllowedPackets);
      await msg2[0].decrypt(algo, key);
      expect(await stream.readToEnd(msg2[0].packets[0].data)).to.deep.equal(literal.data);
    } finally {
      randomBytesStub.restore();
    }
  });

  it('Sym. encrypted session key with a compressed packet', async function() {
    const msg =
        '-----BEGIN PGP MESSAGE-----\n' +
        'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
        '\n' +
        'jA0ECQMCpo7I8WqsebTJ0koBmm6/oqdHXJU9aPe+Po+nk/k4/PZrLmlXwz2lhqBg\n' +
        'GAlY9rxVStLBrg0Hn+5gkhyHI9B85rM1BEYXQ8pP5CSFuTwbJ3O2s67dzQ==\n' +
        '=VZ0/\n' +
        '-----END PGP MESSAGE-----';

    const msgbytes = (await openpgp.unarmor(msg)).data;

    const parsed = new openpgp.PacketList();
    await parsed.read(msgbytes, allAllowedPackets);
    const [skesk, seip] = parsed;

    await skesk.decrypt('test');
    return seip.decrypt(skesk.sessionKeyAlgorithm, skesk.sessionKey).then(async () => {
      const compressed = seip.packets[0];

      const result = await stringify(compressed.packets[0].data);

      expect(result).to.equal('Hello world!\n');
    });
  });

  it('Public key encrypted symmetric key packet', function() {
    const rsa = openpgp.enums.publicKey.rsaEncryptSign;
    const keySize = 1024;

    return crypto.generateParams(rsa, keySize, 65537).then(function({ publicParams, privateParams }) {
      const enc = new openpgp.PublicKeyEncryptedSessionKeyPacket();
      enc.version = 3
      const msg = new openpgp.PacketList();
      const msg2 = new openpgp.PacketList();

      enc.sessionKey = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
      enc.publicKeyAlgorithm = openpgp.enums.publicKey.rsaEncryptSign;
      enc.sessionKeyAlgorithm = openpgp.enums.symmetric.aes256;
      enc.publicKeyID.bytes = '12345678';
      return enc.encrypt({ publicParams, getFingerprintBytes() {} }).then(async () => {

        msg.push(enc);
        await msg2.read(msg.write(), allAllowedPackets);

        const privateKey = { algorithm: openpgp.enums.publicKey.rsaEncryptSign, publicParams, privateParams, getFingerprintBytes() {} };
        return msg2[0].decrypt(privateKey).then(() => {
          expect(stringify(msg2[0].sessionKey)).to.equal(stringify(enc.sessionKey));
          expect(msg2[0].sessionKeyAlgorithm).to.equal(enc.sessionKeyAlgorithm);
        });
      });
    });
  });

  it('Secret key packet (reading, unencrypted)', async function() {
    const armored_key =
        '-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
        'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
        '\n' +
        'lQHYBFF33iMBBAC9YfOYahJlWrVj2J1TjQiZLunWljI4G9e6ARTyD99nfOkV3swh\n' +
        '0WaOse4Utj7BfTqdYcoezhCaQpuExUupKWZqmduBcwSmEBfNu1XyKcxlDQuuk0Vk\n' +
        'viGC3kFRce/cJaKVFSRU8V5zPgt6KQNv/wNz7ydEisaSoNbk51vQt5oGfwARAQAB\n' +
        'AAP5AVL8xWMuKgLj9g7/wftMH+jO7vhAxje2W3Y+8r8TnOSn0536lQvzl/eQyeLC\n' +
        'VK2k3+7+trgO7I4KuXCXZqgAbEi3niDYXDaCJ+8gdR9qvPM2gi9NM71TGXZvGE0w\n' +
        'X8gIZfqLTQWKm9TIS/3tdrth4nwhiye0ASychOboIiN6VIECAMbCQ4/noxGV6yTK\n' +
        'VezsGSz+iCMxz2lV270/Ac2C5WPk+OlxXloxUXeEkGIr6Xkmhhpceed2KL41UC8Y\n' +
        'w5ttGIECAPPsahniKGyqp9CHy6W0B83yhhcIbmLlaVG2ftKyUEDxIggzOlXuVrue\n' +
        'z9XRd6wFqwDd1QMFW0uUyHPDCIFPnv8CAJaDFSZutuWdWMt15NZXjfgRgfJuDrtv\n' +
        'E7yFY/p0el8lCihOT8WoHbTn1PbCYMzNBc0IhHaZKAtA2pjkE+wzz9ClP7QbR2Vv\n' +
        'cmdlIDxnZW9yZ2VAZXhhbXBsZS5jb20+iLkEEwECACMFAlF33iMCGwMHCwkIBwMC\n' +
        'AQYVCAIJCgsEFgIDAQIeAQIXgAAKCRBcqs36fwJCXRbvA/9LPiK6WFKcFoNBnLEJ\n' +
        'mS/CNkL8yTpkslpCP6+TwJMc8uXqwYl9/PW2+CwmzZjs6JsvTzMcR/ZbfZJuSW6Y\n' +
        'EsLNejsSpgcY9aiewGtE+53e5oKYnlmVMTWOPywciIgMvXlzdGhxcwqJ8u0hT+ug\n' +
        '9CjcAfuX9yw85LwXtdGwNh7J8Q==\n' +
        '=lKiS\n' +
        '-----END PGP PRIVATE KEY BLOCK-----';

    let key = new openpgp.PacketList();
    await key.read((await openpgp.unarmor(armored_key)).data, allAllowedPackets);
    key = key[0];

    const enc = new openpgp.PublicKeyEncryptedSessionKeyPacket();
    enc.version = 3
    const secret = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);

    enc.sessionKey = secret;
    enc.publicKeyAlgorithm = openpgp.enums.publicKey.rsaEncryptSign;
    enc.sessionKeyAlgorithm = openpgp.enums.symmetric.aes256;
    enc.publicKeyID.bytes = '12345678';

    return enc.encrypt(key).then(() => {
      return enc.decrypt(key).then(() => {
        expect(stringify(enc.sessionKey)).to.equal(stringify(secret));
      });
    });
  });

  it('Public key encrypted packet (reading, GPG)', async function() {
    const armored_key =
        '-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
        'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
        '\n' +
        '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\n' +
        '=FSwA\n' +
        '-----END PGP PRIVATE KEY BLOCK-----';

    const armored_msg =
        '-----BEGIN PGP MESSAGE-----\n' +
        'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
        '\n' +
        'hIwDFYET+7bfx/ABA/95Uc9942Tg8oqpO0vEu2eSKwPALM3a0DrVdAiFOIK/dJmZ\n' +
        'YrtPRw3EEwHZjl6CO9RD+95iE27tPbsICw1K43gofSV/wWsPO6vvs3eftQYHSxxa\n' +
        'IQbTPImiRaJ73Mf7iM3CNtQM4iUBsx1HnUGl+rtD0nz3fLm6i3CjwiNQWW42I9JH\n' +
        'AWv8EvvpxZ8X2ClFfSW3UVBoROHe9CAWHM/40nGutAZK8MIgmUI4xqkLFBbqqTyx\n' +
        '/cDSC4Q+sv65UX4urbfc7uJuk1Cpj54=\n' +
        '=iSaK\n' +
        '-----END PGP MESSAGE-----';

    let key = new openpgp.PacketList();
    await key.read((await openpgp.unarmor(armored_key)).data, allAllowedPackets);
    key = key[3];

    const msg = new openpgp.PacketList();
    await msg.read((await openpgp.unarmor(armored_msg)).data, allAllowedPackets);

    return msg[0].decrypt(key).then(async () => {
      await msg[1].decrypt(msg[0].sessionKeyAlgorithm, msg[0].sessionKey);

      const text = await stringify(msg[1].packets[0].packets[0].data);

      expect(text).to.equal('Hello world!');
    });
  });

  it('Public key encrypted packet (reading, v6)', async function() {
    // RSA v6 decryption key and signed/encrypted message produced by gopenpgp
    // msg: PKESKv6 SEIPDv2(OPSv6|LD|SIGv6)
    const armored_key =
        '-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
        '\n' +
        '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\n' +
        'SCfmYTfS6Q9zsjOIRaR/OBxpCaF6\n' +
        '=Xrur\n' +
        '-----END PGP PRIVATE KEY BLOCK-----';

    const armored_msg =
        '-----BEGIN PGP MESSAGE-----\n' +
        '\n' +
        'wcBmBiEG+C4NM9PbGvO2RyLA9hVrFkKck2riJ5ydxrHEDCHIFtIBB/9gRZ8oeVyv\n' +
        'kDMWG0fZFRkbnoSIkwbklwMOD1obnkwSAxRhcsKlZ+xXDMfFKbC//mtZ0Vj3I2Ys\n' +
        'h25/IZ3qn5MxiisO1xl++qfCMnI7+y1ETwd6qGyusNXQPAReU5jUNNfy/NKChSIo\n' +
        's/3VbB1w63mN2M2Mytm1GF2ujwT3MqXKSs4tvcLgtwSnKYPTDkj/xS7vwOHjdyTg\n' +
        'Jc4c6B2+Fy98kD780LWF0x0sAVPSc+lbw0tsND6IwgSI2OLbdcTnNHafvr60VKB5\n' +
        '33oFK95bECPCnKNwIcq2vOJ6/WmPvpGE6NlJfTFm0n2hJlKgV9KJNC5oHGSFCNMw\n' +
        'xmzlGdbHq/Ap0sEcAgcDDAj9CmjD1Irn624SUkVRAFWs2kusRxJQUETtP72oehfL\n' +
        'NHAAFccQfKY9JGsIkZf5bh3vG51CU4+C1LNPbqxC8qD/0/I6CnWuCqJu5S1Mbsqr\n' +
        'jp6gm5hYh/SfqNfKgdU0NZ4EkgoVWXILidFSeSIdO08XeX/NcJ96YSxt4qITfawm\n' +
        'Gf5hCukONkI9KP5io+Q5WWa0DhOlpMjTLxtzvBpGdM7TU853lpv3I19yuV4XZP05\n' +
        'NCwdDbI16BqlnmwBBTTwgqh8zhcPfml8AiKsMAjN3pUu0tL5mKfwxtnYrwX4RQvt\n' +
        'Dh/RlBcFHA0a8qGjuZZZCEXUhUM4J5q0kx1X5r3arYaV9vhvO0rprMHrGdKCxOkh\n' +
        'pNVCwt1AUFgijccuHYyjl+pecQdhuHGbYwaMVMbJ9IoYYJ9fjLiSATG51dVZmKi9\n' +
        'Pyjb6hXnWKMJJfTSbjZvYHHOedRbZGGBFs/JPWA1CBiNIkJyIOelI8cMiRvMlWVT\n' +
        'TD2VXAwDnQ3u2sFXY7uRKdMsxkWIeMpy0j5Ib28KCjxCsvop2H2D1r4gcKFl+L49\n' +
        'VqW+RfTZYTRV6dn5OEdcjX2nQNQAIjD+W24VnCzzGqF6H/3Hix9mK5wh4+2o3EjQ\n' +
        'SiSZpkBEbHk=\n' +
        '=U0DE\n' +
        '-----END PGP MESSAGE-----';

    let key = new openpgp.PacketList();
    await key.read((await openpgp.unarmor(armored_key)).data, allAllowedPackets);
    key = key[4];

    const msg = new openpgp.PacketList();
    await msg.read((await openpgp.unarmor(armored_msg)).data, allAllowedPackets);

    return msg[0].decrypt(key).then(async () => {
      await msg[1].decrypt(msg[0].sessionKeyAlgorithm, msg[0].sessionKey);

      const text = await stringify(msg[1].packets[1].data);

      expect(text).to.equal('Hello there');
    });
  });

  it('Sym. encrypted session key reading/writing (CFB)', async function() {
    const aeadProtectVal = openpgp.config.aeadProtect;
    openpgp.config.aeadProtect = false;

    try {
      const passphrase = 'hello';
      const algo = openpgp.enums.symmetric.aes256;
      const testText = input.createSomeMessage();

      const literal = new openpgp.LiteralDataPacket();
      literal.setText(testText);
      const skesk = new openpgp.SymEncryptedSessionKeyPacket();
      const seip = new openpgp.SymEncryptedIntegrityProtectedDataPacket();
      seip.packets = new openpgp.PacketList();
      seip.packets.push(literal);
      const msg = new openpgp.PacketList();

      msg.push(skesk);
      msg.push(seip);

      skesk.sessionKeyAlgorithm = algo;
      await skesk.encrypt(passphrase, openpgp.config);

      const key = skesk.sessionKey;
      await seip.encrypt(algo, key, undefined, openpgp.config);

      const msg2 = new openpgp.PacketList();
      await msg2.read(msg.write(), allAllowedPackets);

      await msg2[0].decrypt(passphrase);
      const key2 = msg2[0].sessionKey;
      await msg2[1].decrypt(msg2[0].sessionKeyAlgorithm, key2);

      expect(await stringify(msg2[1].packets[0].data)).to.equal(stringify(literal.data));
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
    }
  });

  it('Sym. encrypted session key reading/writing (AEAD)', async function() {
    const aeadProtectVal = openpgp.config.aeadProtect;
    openpgp.config.aeadProtect = true;

    try {
      const passphrase = 'hello';
      const algo = openpgp.enums.symmetric.aes256;
      const testText = input.createSomeMessage();

      const literal = new openpgp.LiteralDataPacket();
      literal.setText(testText);
      const skesk = new openpgp.SymEncryptedSessionKeyPacket();
      skesk.version = 5;
      const aeadEnc = new openpgp.AEADEncryptedDataPacket();
      aeadEnc.packets = new openpgp.PacketList();
      aeadEnc.packets.push(literal);
      const msg = new openpgp.PacketList();
      msg.push(skesk);
      msg.push(aeadEnc);

      skesk.sessionKeyAlgorithm = algo;
      await skesk.encrypt(passphrase, openpgp.config);

      const key = skesk.sessionKey;
      await aeadEnc.encrypt(algo, key, undefined, openpgp.config);

      const msg2 = new openpgp.PacketList();
      await msg2.read(msg.write(), allAllowedPackets);

      await msg2[0].decrypt(passphrase);
      const key2 = msg2[0].sessionKey;
      await msg2[1].decrypt(msg2[0].sessionKeyAlgorithm, key2);

      expect(await stringify(msg2[1].packets[0].data)).to.equal(stringify(literal.data));
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
    }
  });

  it('Sym. encrypted session key reading/writing (SEIPDv2)', async function() {
    const aeadProtectVal = openpgp.config.aeadProtect;
    openpgp.config.aeadProtect = true;

    try {
      const passphrase = 'hello';
      const algo = openpgp.enums.symmetric.aes256;
      const testText = input.createSomeMessage();

      const literal = new openpgp.LiteralDataPacket();
      literal.setText(testText);
      const skesk = new openpgp.SymEncryptedSessionKeyPacket();
      const aeadEnc = new openpgp.AEADEncryptedDataPacket();
      aeadEnc.packets = new openpgp.PacketList();
      aeadEnc.packets.push(literal);
      const msg = new openpgp.PacketList();
      msg.push(skesk);
      msg.push(aeadEnc);

      skesk.sessionKeyAlgorithm = algo;
      await skesk.encrypt(passphrase, openpgp.config);

      const key = skesk.sessionKey;
      await aeadEnc.encrypt(algo, key, undefined, openpgp.config);

      const msg2 = new openpgp.PacketList();
      await msg2.read(msg.write(), allAllowedPackets);

      await msg2[0].decrypt(passphrase);
      const key2 = msg2[0].sessionKey;
      await msg2[1].decrypt(msg2[0].sessionKeyAlgorithm, key2);

      expect(await stringify(msg2[1].packets[0].data)).to.equal(stringify(literal.data));
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
    }
  });

  it('Sym. encrypted session key reading/writing test vector (AEAD, EAX)', async function() {
    // From https://gitlab.com/openpgp-wg/rfc4880bis/blob/00b20923/back.mkd#sample-aead-eax-encryption-and-decryption

    const nodeCrypto = util.getNodeCrypto();
    if (!nodeCrypto) return;

    const aeadProtectVal = openpgp.config.aeadProtect;
    const aeadChunkSizeByteVal = openpgp.config.aeadChunkSizeByte;
    const s2kIterationCountByteVal = openpgp.config.s2kIterationCountByte;
    openpgp.config.aeadProtect = true;
    openpgp.config.aeadChunkSizeByte = 14;
    openpgp.config.s2kIterationCountByte = 0x90;

    const salt = util.hexToUint8Array('cd5a9f70fbe0bc65');
    const sessionKey = util.hexToUint8Array('86 f1 ef b8 69 52 32 9f 24 ac d3 bf d0 e5 34 6d'.replace(/\s+/g, ''));
    const sessionIV = util.hexToUint8Array('bc 66 9e 34 e5 00 dc ae dc 5b 32 aa 2d ab 02 35'.replace(/\s+/g, ''));
    const dataIV = util.hexToUint8Array('b7 32 37 9f 73 c4 92 8d e2 5f ac fe 65 17 ec 10'.replace(/\s+/g, ''));

    const randomBytesStub = stub(nodeCrypto, 'randomBytes');
    randomBytesStub.onCall(0).returns(salt);
    randomBytesStub.onCall(1).returns(sessionKey);
    randomBytesStub.onCall(2).returns(sessionIV);
    randomBytesStub.onCall(3).returns(dataIV);

    const packetBytes = util.hexToUint8Array(`
      c3 3e 05 07 01 03 08 cd  5a 9f 70 fb e0 bc 65 90
      bc 66 9e 34 e5 00 dc ae  dc 5b 32 aa 2d ab 02 35
      9d ee 19 d0 7c 34 46 c4  31 2a 34 ae 19 67 a2 fb
      7e 92 8e a5 b4 fa 80 12  bd 45 6d 17 38 c6 3c 36

      d4 4a 01 07 01 0e b7 32  37 9f 73 c4 92 8d e2 5f
      ac fe 65 17 ec 10 5d c1  1a 81 dc 0c b8 a2 f6 f3
      d9 00 16 38 4a 56 fc 82  1a e1 1a e8 db cb 49 86
      26 55 de a8 8d 06 a8 14  86 80 1b 0f f3 87 bd 2e
      ab 01 3d e1 25 95 86 90  6e ab 24 76
    `.replace(/\s+/g, ''));

    try {
      const passphrase = 'password';
      const algo = openpgp.enums.symmetric.aes128;

      const literal = new openpgp.LiteralDataPacket(0);
      literal.setBytes(util.stringToUint8Array('Hello, world!\n'), openpgp.enums.literal.binary);
      literal.filename = '';
      const skesk = new openpgp.SymEncryptedSessionKeyPacket();
      skesk.version = 5;
      skesk.sessionKeyAlgorithm = algo;
      const encData = new openpgp.AEADEncryptedDataPacket();
      encData.packets = new openpgp.PacketList();
      encData.packets.push(literal);
      encData.aeadAlgorithm = skesk.aeadAlgorithm = openpgp.enums.aead.eax;
      const msg = new openpgp.PacketList();
      msg.push(skesk);
      msg.push(encData);

      await skesk.encrypt(passphrase, openpgp.config);

      const key = skesk.sessionKey;
      await encData.encrypt(algo, key, undefined, openpgp.config);

      const data = msg.write();
      expect(await stream.readToEnd(stream.clone(data))).to.deep.equal(packetBytes);

      const msg2 = new openpgp.PacketList();
      await msg2.read(data, allAllowedPackets);

      await msg2[0].decrypt(passphrase);
      const key2 = msg2[0].sessionKey;
      await msg2[1].decrypt(msg2[0].sessionKeyAlgorithm, key2);

      expect(await stringify(msg2[1].packets[0].data)).to.equal(stringify(literal.data));
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
      openpgp.config.aeadChunkSizeByte = aeadChunkSizeByteVal;
      openpgp.config.s2kIterationCountByte = s2kIterationCountByteVal;
      randomBytesStub.restore();
    }
  });

  it('Sym. encrypted session key reading/writing test vector (AEAD, OCB)', async function() {
    // From https://gitlab.com/openpgp-wg/rfc4880bis/blob/00b20923/back.mkd#sample-aead-ocb-encryption-and-decryption

    const nodeCrypto = util.getNodeCrypto();
    if (!nodeCrypto) return;

    const aeadProtectVal = openpgp.config.aeadProtect;
    const aeadChunkSizeByteVal = openpgp.config.aeadChunkSizeByte;
    const s2kIterationCountByteVal = openpgp.config.s2kIterationCountByte;
    openpgp.config.aeadProtect = true;
    openpgp.config.aeadChunkSizeByte = 14;
    openpgp.config.s2kIterationCountByte = 0x90;

    const salt = util.hexToUint8Array('9f0b7da3e5ea6477');
    const sessionKey = util.hexToUint8Array('d1 f0 1b a3 0e 13 0a a7 d2 58 2c 16 e0 50 ae 44'.replace(/\s+/g, ''));
    const sessionIV = util.hexToUint8Array('99 e3 26 e5 40 0a 90 93 6c ef b4 e8 eb a0 8c'.replace(/\s+/g, ''));
    const dataIV = util.hexToUint8Array('5e d2 bc 1e 47 0a be 8f 1d 64 4c 7a 6c 8a 56'.replace(/\s+/g, ''));

    const randomBytesStub = stub(nodeCrypto, 'randomBytes');
    randomBytesStub.onCall(0).returns(salt);
    randomBytesStub.onCall(1).returns(sessionKey);
    randomBytesStub.onCall(2).returns(sessionIV);
    randomBytesStub.onCall(3).returns(dataIV);

    const packetBytes = util.hexToUint8Array(`
      c3 3d 05 07 02 03 08 9f  0b 7d a3 e5 ea 64 77 90
      99 e3 26 e5 40 0a 90 93  6c ef b4 e8 eb a0 8c 67
      73 71 6d 1f 27 14 54 0a  38 fc ac 52 99 49 da c5
      29 d3 de 31 e1 5b 4a eb  72 9e 33 00 33 db ed

      d4 49 01 07 02 0e 5e d2  bc 1e 47 0a be 8f 1d 64
      4c 7a 6c 8a 56 7b 0f 77  01 19 66 11 a1 54 ba 9c
      25 74 cd 05 62 84 a8 ef  68 03 5c 62 3d 93 cc 70
      8a 43 21 1b b6 ea f2 b2  7f 7c 18 d5 71 bc d8 3b
      20 ad d3 a0 8b 73 af 15  b9 a0 98
    `.replace(/\s+/g, ''));

    try {
      const passphrase = 'password';
      const algo = openpgp.enums.symmetric.aes128;

      const literal = new openpgp.LiteralDataPacket(0);
      literal.setBytes(util.stringToUint8Array('Hello, world!\n'), openpgp.enums.literal.binary);
      literal.filename = '';
      const skesk = new openpgp.SymEncryptedSessionKeyPacket();
      skesk.version = 5;
      skesk.sessionKeyAlgorithm = algo;
      const enc = new openpgp.AEADEncryptedDataPacket();
      enc.packets = new openpgp.PacketList();
      enc.packets.push(literal);
      enc.aeadAlgorithm = skesk.aeadAlgorithm = openpgp.enums.aead.ocb;
      const msg = new openpgp.PacketList();
      msg.push(skesk);
      msg.push(enc);

      await skesk.encrypt(passphrase, openpgp.config);

      const key = skesk.sessionKey;
      await enc.encrypt(algo, key, undefined, openpgp.config);

      const data = msg.write();
      expect(await stream.readToEnd(stream.clone(data))).to.deep.equal(packetBytes);

      const msg2 = new openpgp.PacketList();
      await msg2.read(data, allAllowedPackets);

      await msg2[0].decrypt(passphrase);
      const key2 = msg2[0].sessionKey;
      await msg2[1].decrypt(msg2[0].sessionKeyAlgorithm, key2);

      expect(await stringify(msg2[1].packets[0].data)).to.equal(stringify(literal.data));
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
      openpgp.config.aeadChunkSizeByte = aeadChunkSizeByteVal;
      openpgp.config.s2kIterationCountByte = s2kIterationCountByteVal;
      randomBytesStub.restore();
    }
  });

  it('Sym. encrypted session key reading/writing test vector (SEIPDv2, EAX)', async function() {
    // From https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#appendix-A.5

    const nodeCrypto = util.getNodeCrypto();
    if (!nodeCrypto) return;

    const aeadProtectVal = openpgp.config.aeadProtect;
    const aeadChunkSizeByteVal = openpgp.config.aeadChunkSizeByte;
    const s2kIterationCountByteVal = openpgp.config.s2kIterationCountByte;
    openpgp.config.aeadProtect = true;
    openpgp.config.aeadChunkSizeByte = 6;
    openpgp.config.s2kIterationCountByte = 255;

    const padding = util.hexToUint8Array('ae 5b f0 cd 67 05 50 03 55 81 6c b0 c8 ff'.replace(/\s+/g, ''));
    const salt = util.hexToUint8Array('a5 ae 57 9d 1f c5 d8 2b'.replace(/\s+/g, ''));
    const sessionKey = util.hexToUint8Array('38 81 ba fe 98 54 12 45 9b 86 c3 6f 98 cb 9a 5e'.replace(/\s+/g, ''));
    const sessionIV = util.hexToUint8Array('69 22 4f 91 99 93 b3 50 6f a3 b5 9a 6a 73 cf f8'.replace(/\s+/g, ''));
    const dataSalt = util.hexToUint8Array('9f f9 0e 3b 32 19 64 f3 a4 29 13 c8 dc c6 61 93 25 01 52 27 ef b7 ea ea a4 9f 04 c2 e6 74 17 5d'.replace(/\s+/g, ''));

    const randomBytesStub = stub(nodeCrypto, 'randomBytes');
    randomBytesStub.onCall(0).returns(padding);
    randomBytesStub.onCall(1).returns(salt);
    randomBytesStub.onCall(2).returns(sessionKey);
    randomBytesStub.onCall(3).returns(sessionIV);
    randomBytesStub.onCall(4).returns(dataSalt);

    const { data: packetBytes } = await openpgp.unarmor(`-----BEGIN PGP MESSAGE-----

w0AGHgcBCwMIpa5XnR/F2Cv/aSJPkZmTs1Bvo7WaanPP+MXvxfQcV/tU4cImgV14
KPX5LEVOtl6+AKtZhsaObnxV0mkCBwEGn/kOOzIZZPOkKRPI3MZhkyUBUifvt+rq
pJ8EwuZ0F11KPSJu1q/LnKmsEiwUcOEcY9TAqyQcapOK1Iv5mlqZuQu6gyXeYQR1
QCWKt5Wala0FHdqW6xVDHf719eIlXKeCYVRuM5o=
-----END PGP MESSAGE-----
`);

    try {
      const passphrase = 'password';
      const algo = openpgp.enums.symmetric.aes128;

      const skesk = new openpgp.SymEncryptedSessionKeyPacket();
      skesk.sessionKeyAlgorithm = algo;
      const literal = new openpgp.LiteralDataPacket(0);
      literal.setBytes(util.stringToUint8Array('Hello, world!'), openpgp.enums.literal.binary);
      literal.filename = '';
      const pad = new openpgp.PaddingPacket();
      await pad.createPadding(14);
      const enc = new openpgp.SymEncryptedIntegrityProtectedDataPacket();
      enc.version = 2;
      enc.aeadAlgorithm = skesk.aeadAlgorithm = openpgp.enums.aead.eax;
      enc.packets = new openpgp.PacketList();
      enc.packets.push(literal);
      enc.packets.push(pad);
      const msg = new openpgp.PacketList();
      msg.push(skesk);
      msg.push(enc);

      await skesk.encrypt(passphrase, openpgp.config);

      const key = skesk.sessionKey;
      await enc.encrypt(algo, key, undefined, openpgp.config);

      const data = msg.write();
      expect(await stream.readToEnd(stream.clone(data))).to.deep.equal(packetBytes);

      const msg2 = new openpgp.PacketList();
      await msg2.read(data, allAllowedPackets);

      await msg2[0].decrypt(passphrase);
      const key2 = msg2[0].sessionKey;
      await msg2[1].decrypt(msg2[0].sessionKeyAlgorithm, key2);

      expect(await stringify(msg2[1].packets[0].data)).to.equal(stringify(literal.data));
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
      openpgp.config.aeadChunkSizeByte = aeadChunkSizeByteVal;
      openpgp.config.s2kIterationCountByte = s2kIterationCountByteVal;
      randomBytesStub.restore();
    }
  });

  it('Sym. encrypted session key reading/writing test vector (SEIPDv2, OCB)', async function() {
    // From https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#appendix-A.6

    const nodeCrypto = util.getNodeCrypto();
    if (!nodeCrypto) return;

    const aeadProtectVal = openpgp.config.aeadProtect;
    const aeadChunkSizeByteVal = openpgp.config.aeadChunkSizeByte;
    const s2kIterationCountByteVal = openpgp.config.s2kIterationCountByte;
    openpgp.config.aeadProtect = true;
    openpgp.config.aeadChunkSizeByte = 6;
    openpgp.config.s2kIterationCountByte = 255;

    const padding = util.hexToUint8Array('ae 6a a1 64 9b 56 aa 83 5b 26 13 90 2b d2'.replace(/\s+/g, ''));
    const salt = util.hexToUint8Array('56 a2 98 d2 f5 e3 64 53'.replace(/\s+/g, ''));
    const sessionKey = util.hexToUint8Array('28 e7 9a b8 23 97 d3 c6 3d e2 4a c2 17 d7 b7 91'.replace(/\s+/g, ''));
    const sessionIV = util.hexToUint8Array('cf cc 5c 11 66 4e db 9d b4 25 90 d7 dc 46 b0'.replace(/\s+/g, ''));
    const dataSalt = util.hexToUint8Array('20 a6 61 f7 31 fc 9a 30 32 b5 62 33 26 02 7e 3a 5d 8d b5 74 8e be ff 0b 0c 59 10 d0 9e cd d6 41'.replace(/\s+/g, ''));

    const randomBytesStub = stub(nodeCrypto, 'randomBytes');
    randomBytesStub.onCall(0).returns(padding);
    randomBytesStub.onCall(1).returns(salt);
    randomBytesStub.onCall(2).returns(sessionKey);
    randomBytesStub.onCall(3).returns(sessionIV);
    randomBytesStub.onCall(4).returns(dataSalt);

    const { data: packetBytes } = await openpgp.unarmor(`-----BEGIN PGP MESSAGE-----

wz8GHQcCCwMIVqKY0vXjZFP/z8xcEWZO2520JZDX3EawckG2EsOBLP/76gDyNHsl
ZBEj+IeuYNT9YU4IN9gZ02zSaQIHAgYgpmH3MfyaMDK1YjMmAn46XY21dI6+/wsM
WRDQns3WQf+f04VidYA1vEl1TOG/P/+n2tCjuBBPUTPPQqQQCoPu9MobSAGohGv0
K82nyM6dZeIS8wHLzZj9yt5pSod61CRzI/boVw==
-----END PGP MESSAGE-----
`);

    try {
      const passphrase = 'password';
      const algo = openpgp.enums.symmetric.aes128;

      const skesk = new openpgp.SymEncryptedSessionKeyPacket();
      skesk.sessionKeyAlgorithm = algo;
      const literal = new openpgp.LiteralDataPacket(0);
      literal.setBytes(util.stringToUint8Array('Hello, world!'), openpgp.enums.literal.binary);
      literal.filename = '';
      const pad = new openpgp.PaddingPacket();
      await pad.createPadding(14);
      const enc = new openpgp.SymEncryptedIntegrityProtectedDataPacket();
      enc.version = 2;
      enc.aeadAlgorithm = skesk.aeadAlgorithm = openpgp.enums.aead.ocb;
      enc.packets = new openpgp.PacketList();
      enc.packets.push(literal);
      enc.packets.push(pad);
      const msg = new openpgp.PacketList();
      msg.push(skesk);
      msg.push(enc);

      await skesk.encrypt(passphrase, openpgp.config);

      const key = skesk.sessionKey;
      await enc.encrypt(algo, key, undefined, openpgp.config);

      const data = msg.write();
      expect(await stream.readToEnd(stream.clone(data))).to.deep.equal(packetBytes);

      const msg2 = new openpgp.PacketList();
      await msg2.read(data, allAllowedPackets);

      await msg2[0].decrypt(passphrase);
      const key2 = msg2[0].sessionKey;
      await msg2[1].decrypt(msg2[0].sessionKeyAlgorithm, key2);

      expect(await stringify(msg2[1].packets[0].data)).to.equal(stringify(literal.data));
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
      openpgp.config.aeadChunkSizeByte = aeadChunkSizeByteVal;
      openpgp.config.s2kIterationCountByte = s2kIterationCountByteVal;
      randomBytesStub.restore();
    }
  });

  it('Sym. encrypted session key reading/writing test vector (SEIPDv2, GCM)', async function() {
    // From https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#appendix-A.7

    const nodeCrypto = util.getNodeCrypto();
    if (!nodeCrypto) return;

    const aeadProtectVal = openpgp.config.aeadProtect;
    const aeadChunkSizeByteVal = openpgp.config.aeadChunkSizeByte;
    const s2kIterationCountByteVal = openpgp.config.s2kIterationCountByte;
    openpgp.config.aeadProtect = true;
    openpgp.config.aeadChunkSizeByte = 6;
    openpgp.config.s2kIterationCountByte = 255;

    const padding = util.hexToUint8Array('1c e2 26 9a 9e dd ef 81 03 21 72 b7 ed 7c'.replace(/\s+/g, ''));
    const salt = util.hexToUint8Array('e9 d3 97 85 b2 07 00 08'.replace(/\s+/g, ''));
    const sessionKey = util.hexToUint8Array('19 36 fc 85 68 98 02 74 bb 90 0d 83 19 36 0c 77'.replace(/\s+/g, ''));
    const sessionIV = util.hexToUint8Array('b4 2e 7c 48 3e f4 88 44 57 cb 37 26'.replace(/\s+/g, ''));
    const dataSalt = util.hexToUint8Array('fc b9 44 90 bc b9 8b bd c9 d1 06 c6 09 02 66 94 0f 72 e8 9e dc 21 b5 59 6b 15 76 b1 01 ed 0f 9f'.replace(/\s+/g, ''));

    const randomBytesStub = stub(nodeCrypto, 'randomBytes');
    randomBytesStub.onCall(0).returns(padding);
    randomBytesStub.onCall(1).returns(salt);
    randomBytesStub.onCall(2).returns(sessionKey);
    randomBytesStub.onCall(3).returns(sessionIV);
    randomBytesStub.onCall(4).returns(dataSalt);

    const { data: packetBytes } = await openpgp.unarmor(`-----BEGIN PGP MESSAGE-----

wzwGGgcDCwMI6dOXhbIHAAj/tC58SD70iERXyzcmubPbn/d25fTZpAlS4kRymIUa
v/91Jt8t1VRBdXmneZ/SaQIHAwb8uUSQvLmLvcnRBsYJAmaUD3LontwhtVlrFXax
Ae0Pn/xvxtZbv9JNzQeQlm5tHoWjAFN4TLHYtqBpnvEhVaeyrWJYUxtXZR/Xd3kS
+pXjXZtAIW9ppMJI2yj/QzHxYykHOZ5v+Q==
-----END PGP MESSAGE-----
`);

    try {
      const passphrase = 'password';
      const algo = openpgp.enums.symmetric.aes128;

      const skesk = new openpgp.SymEncryptedSessionKeyPacket();
      skesk.sessionKeyAlgorithm = algo;
      const literal = new openpgp.LiteralDataPacket(0);
      literal.setBytes(util.stringToUint8Array('Hello, world!'), openpgp.enums.literal.binary);
      literal.filename = '';
      const pad = new openpgp.PaddingPacket();
      await pad.createPadding(14);
      const enc = new openpgp.SymEncryptedIntegrityProtectedDataPacket();
      enc.version = 2;
      enc.aeadAlgorithm = skesk.aeadAlgorithm = openpgp.enums.aead.gcm;
      enc.packets = new openpgp.PacketList();
      enc.packets.push(literal);
      enc.packets.push(pad);
      const msg = new openpgp.PacketList();
      msg.push(skesk);
      msg.push(enc);

      await skesk.encrypt(passphrase, openpgp.config);

      const key = skesk.sessionKey;
      await enc.encrypt(algo, key, undefined, openpgp.config);

      const data = msg.write();
      expect(await stream.readToEnd(stream.clone(data))).to.deep.equal(packetBytes);

      const msg2 = new openpgp.PacketList();
      await msg2.read(data, allAllowedPackets);

      await msg2[0].decrypt(passphrase);
      const key2 = msg2[0].sessionKey;
      await msg2[1].decrypt(msg2[0].sessionKeyAlgorithm, key2);

      expect(await stringify(msg2[1].packets[0].data)).to.equal(stringify(literal.data));
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
      openpgp.config.aeadChunkSizeByte = aeadChunkSizeByteVal;
      openpgp.config.s2kIterationCountByte = s2kIterationCountByteVal;
      randomBytesStub.restore();
    }
  });

  it('Secret key encryption/decryption test', async function() {
    const armored_msg =
        '-----BEGIN PGP MESSAGE-----\n' +
        'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
        '\n' +
        'hIwD95D9aHS5fxEBA/98CwH54XZmwobOmHUcvWcDDQysBEC4uf7wASiGcRbejDaO\n' +
        'aJqcrK/3k8sBQMO7yOhvrCRqqpGDqnmx7IaaKLnZS7nYAZoHEsK9UyG0hDa8Cfbo\n' +
        'CP4xZVcgIvIfAW/in1LeT2td0QcQNbeewBmPea+vQEEvRgIP10tlE7MK8Ay48dJH\n' +
        'AagMgNYg7MBUjpuOCVrjM1pWja8uzbULfYhTq3IJ8H3QhbdT+k9khY9f0aJPEeYi\n' +
        'dVv6DK9uviMGc/DsVCw5K8lQRLlkcHc=\n' +
        '=pR+C\n' +
        '-----END PGP MESSAGE-----';

    const keyPackets = new openpgp.PacketList();
    await keyPackets.read((await openpgp.unarmor(armored_key)).data, allAllowedPackets);
    const keyPacket = keyPackets[3];
    await keyPacket.decrypt('test');

    const msg = new openpgp.PacketList();
    await msg.read((await openpgp.unarmor(armored_msg)).data, allAllowedPackets);

    return msg[0].decrypt(keyPacket).then(async () => {
      await msg[1].decrypt(msg[0].sessionKeyAlgorithm, msg[0].sessionKey);

      const text = await stringify(msg[1].packets[0].packets[0].data);

      expect(text).to.equal('Hello world!');
    });
  });

  it('Secret key reading with signature verification.', async function() {
    const packets = await openpgp.PacketList.fromBinary((await openpgp.unarmor(armored_key)).data, allAllowedPackets);
    const [keyPacket, userIDPacket, keySigPacket, subkeyPacket, subkeySigPacket] = packets;

    await keySigPacket.verify(
      keyPacket, openpgp.enums.signature.certGeneric, { userID: userIDPacket, key: keyPacket }
    );
    await subkeySigPacket.verify(
      keyPacket, openpgp.enums.signature.keyBinding, { key: keyPacket, bind: subkeyPacket }
    );
  });

  it('Reading a signed, encrypted message.', async function() {
    const armored_msg =
        '-----BEGIN PGP MESSAGE-----\n' +
        'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
        '\n' +
        'hIwD95D9aHS5fxEBA/4/X4myvH+jB1HYNeZvdK+WsBNDMfLsBGOf205Rxr3vSob/\n' +
        'A09boj8/9lFaipqu+AEdQKEjCB8sZ+OY0WiQPEPpuhG+mVqDqEiPFkdpcqNtS0VV\n' +
        'pwqplHo6QnH2MHfxprZHYuwcEC9ynJCxJ6kSCD8Xs99h+PjxNNw7NhMjkF+N69LA\n' +
        'NwGPtbLx2/r2nR4gO8gV92A2RQCOwPP7ZV+6fXgWIs+mhyCHFP3xUP5DaFCNM8mo\n' +
        'PN97i659ucxF6IbOoK56FEaUbOPTD6xdyhWamxKfMsIb0UJgVUNhGaq+VlvOJxaB\n' +
        'iRcnY5UxsypKgtqfcKIseb21MIo4vcNdogyxBIDlAO472Zfxn0udzr6W2aQ77+NK\n' +
        'FE1O0kCXS+DTFOYYVD7X8rXGSglQsdXJmHd89sdYFQkO7D7bOLdRJuXgdgH2czCs\n' +
        'UBGuHZzsGbTdyKvpVBuS3rnyHHBk6oCnsm1Nl7eLs64VkZUxjEUbq5pb4dlr1pw2\n' +
        'ztpmpAnRcmM=\n' +
        '=htrB\n' +
        '-----END PGP MESSAGE-----';

    const packets = await openpgp.PacketList.fromBinary((await openpgp.unarmor(armored_key)).data, allAllowedPackets);
    const keyPacket = packets[0];
    const subkeyPacket = packets[3];
    await subkeyPacket.decrypt('test');

    const msg = new openpgp.PacketList();
    await msg.read((await openpgp.unarmor(armored_msg)).data, allAllowedPackets);
    const [pkesk, encData] = msg;

    return pkesk.decrypt(subkeyPacket).then(async () => {
      await encData.decrypt(pkesk.sessionKeyAlgorithm, pkesk.sessionKey);

      const payload = encData.packets[0].packets;
      payload.push(...await stream.readToEnd(payload.stream, arr => arr));
      const literal = payload[1];
      const signature = payload[2];

      await Promise.all([
        signature.verify(keyPacket, openpgp.enums.signature.binary, literal),
        stream.readToEnd(literal.getBytes())
      ]);
    });
  });

  it('Reading signersUserID from armored signature', async function() {
    const armoredSignature =
`-----BEGIN PGP SIGNATURE-----

iQFKBAEBCgA0FiEEdOyNPagqedqiXfEMa6Ve2Dq64bsFAlszXwQWHHRlc3Qtd2tk
QG1ldGFjb2RlLmJpegAKCRBrpV7YOrrhuw1PB/9KhFRR/M3OR6NmIent6ri1ekWn
vlcnVqj6N4Xqi1ahRVw19/Jx36mGyijxNwqqGrziqRiPCdT0pKfCfv7nXQf2Up1Z
LoR1StqpBMSDQfuF6JAJmJuB9T+mPQO8wYeUp+O63vQnm5CgqyoRlIoqX8MN6GTY
xK5PdTRjw6IEIGr9uLgSoUwTd0ECY1F9ptyuLGD5ET5ZtyUenQSbX+cw5WCGLFzi
7TwKTY+kGQpkwDJKZJSGpoP7ob6xdDfZx6dHV6IfIJg8/F9gtAXFp8uE51L90cV2
kePFjAnu9cpynKXu3usf8+FuBw2zLsg1Id1n7ttxoAte416KjBN9lFBt8mcu
=wEIR
-----END PGP SIGNATURE-----`;

    const signature = await openpgp.readSignature({ armoredSignature });

    expect(signature.packets[0].signersUserID).to.equal('test-wkd@metacode.biz');
  });

  it('Reading notations from armored key', async function() {
    const pubkey =
`-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFzQOToBCADd0Pwh8edZ6gR3x49L1PaBPtiAQUr1QDUDWeNes8co5MTFl5hG
lHzptt+VD0JGucuIkvi34f5z2ZbInAV/xYDX3kSYefy6LB8XJD527I/o9bqY1P7T
PjtTZ4emcqNGkGhV2hNGV+hFcTevUS9Ty4vGg6P7X6RjfjeTrClHelJT8+9IiH+4
0h4X/Y1hwoijRWanYnZjuAUIrOXnG76iknXQRGc8th8iI0oIZfKQomfF0K5lXFhH
SU8Yvmik3vCTLHC6Ce0GVRCTIcU0/Xi2MK/Yrg9bGzSblHxomLU0NT6pee+2UjqR
BZXOAPLY66Lsh1oqxQ6ihVnOmbraU9glAGm1ABEBAAG0EFRlc3R0IDx0ZXN0QGV4
YT6JAYoEEwEIAHQCGwMFCQPCZwAFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQQZ
jHIqS6wzbp2qrkRXnQGzq+FUDgUCXNA5VBoUgAAAAAAQAAF0ZXN0QGV4YW1wbGUu
Y29tMhoUgAAAAAAQAAF0ZXN0QGV4YW1wbGUuY29tMwAKCRBXnQGzq+FUDoLiCACn
ls1iy0hT59Xt3o3tmmxe1jLzkbQEprR6MMfZamtex5/BHViu2HPAu5i13mXyBRnJ
4Zvd/HUxJukP3tdQyJIlZFe8XwloMoRAA37KOZ5QGyKH8Jxq3LcAcQOOkFtWgr+Z
JbjUKF1IuqCsK6SYB8f7SVKgpZk/kqG3HE3gk72ONnqdvwOa9cIhAuZScdgZ+PLC
6W/0+IrnQIasvKeEWeK4u6/NYT35HUsUE/9Z6WKF+qxJnp5Pi2Q5cio6bFlGDNQb
+MiuiEb3Mzb3ev2PVg7WELBRXOg8QlCxrghqfi1SH791mmiyGK+GIQgnjRwMejTh
dNsnHYag/KAewag55AQvuQENBFzQOToBCADJD+auK+Opo1q3ZLxODMyw5//XHJH4
0vQPNawyBiOdBuneWHF3jfDwGa+lOftUx1abSwsq+Qs955THgLVSiJvivHWVy8pN
tPv0XLa9rMj2wh/OmckbcgzSMeJJIz09bTj095ONPGYW2D4AcpkOc+b5bkqV6r+N
yk9nopPJNCNqYYJtecTClDT5haRKBP5XjXRVsIXva/nHZGXKQLX8iWG2D5DOJNDP
ZkAEoIPg+7J85Q3u2iSFPnLPzKHlMAoQW8d9RAEYyJ6WqiILUIDShhvXg+RIkzri
wY/WkvhB/Kpj0r1SRbNhWRpmOWCR+0a2uHaLz9X0KTP7WMqQbmIdpRgZABEBAAGJ
ATwEGAEIACYWIQQZjHIqS6wzbp2qrkRXnQGzq+FUDgUCXNA5OgIbDAUJA8JnAAAK
CRBXnQGzq+FUDgI6B/9Far0CUR6rWvUiviBY4P5oe44I9P9P7ilWmum1cIQWxMyF
0sc5tRcVLpMomURlrDz0TR5GNs+nuGAHTRBfN7VO0Y+R/LyEd1Rf80ONObXOqzMp
vF9CdW3a7W4WicZwnGgUOImTICazR2VmR+RREdZshqrOCaOnuKmN3QwGH1zzFwJA
sTbLoNMdBv8SEARaRVOWPM1HwJ701mMYF48FqhHd5uinH/ZCeBhqrBfhmXa68FWx
xuyJz6ttl5Fp4nsB3waQdgPGZJ9NUrGfopLUZ44xDuJjBONd7rbYOh71TWbHd8wG
V+HOQJQxXJkVRYa3QrFUehiMzTeqqMdgC6ZqJy7+
=et/d
-----END PGP PUBLIC KEY BLOCK-----`;

    const key = await openpgp.readKey({ armoredKey: pubkey });

    const { notations, rawNotations } = key.users[0].selfCertifications[0];

    // Even though there are two notations with the same keys
    // the `notations` property reads only the single one:
    // the last one encountered during parse
    expect(Object.keys(notations).length).to.equal(1);
    expect(notations['test@example.com']).to.equal('3');

    // On the other hand `rawNotations` property provides access to all
    // notations, even non human-readable. The values are not deserialized
    // and they are byte-arrays.
    expect(rawNotations.length).to.equal(2);

    expect(rawNotations[0].name).to.equal('test@example.com');
    expect(rawNotations[0].value).to.deep.equal(new Uint8Array(['2'.charCodeAt(0)]));
    expect(rawNotations[0].humanReadable).to.equal(true);

    expect(rawNotations[1].name).to.equal('test@example.com');
    expect(rawNotations[1].value).to.deep.equal(new Uint8Array(['3'.charCodeAt(0)]));
    expect(rawNotations[1].humanReadable).to.equal(true);
  });

  it('Writing and encryption of a secret key packet (AEAD)', async function() {
    const rsa = openpgp.enums.publicKey.rsaEncryptSign;
    const { privateParams, publicParams } = await crypto.generateParams(rsa, 1024, 65537);

    const secretKeyPacket = new openpgp.SecretKeyPacket();
    secretKeyPacket.privateParams = privateParams;
    secretKeyPacket.publicParams = publicParams;
    secretKeyPacket.algorithm = openpgp.enums.publicKey.rsaSign;
    secretKeyPacket.isEncrypted = false;
    await secretKeyPacket.encrypt('hello', { ...openpgp.config, aeadProtect: true });
    expect(secretKeyPacket.s2kUsage).to.equal(253);

    const raw = new openpgp.PacketList();
    raw.push(secretKeyPacket);
    const packetList = await openpgp.PacketList.fromBinary(raw.write(), allAllowedPackets, openpgp.config);
    const secretKeyPacket2 = packetList[0];
    await secretKeyPacket2.decrypt('hello');

    expect(secretKeyPacket2.privateParams).to.deep.equal(secretKeyPacket.privateParams);
    expect(secretKeyPacket2.publicParams).to.deep.equal(secretKeyPacket.publicParams);
  });

  it('Writing of unencrypted v6 secret key packet', async function() {
    const originalv6KeysSetting = openpgp.config.v6Keys;
    openpgp.config.v6Keys = true;

    try {
      const packet = new openpgp.SecretKeyPacket();

      packet.privateParams = { key: new Uint8Array([1, 2, 3]) };
      packet.publicParams = { pubKey: new Uint8Array([4, 5, 6]) };
      packet.algorithm = openpgp.enums.publicKey.rsaSign;
      packet.isEncrypted = false;
      packet.s2kUsage = 0;

      const written = packet.write();
      expect(written.length).to.equal(21);

      /**
       * The private data
       *
       * The 2 bytes missing here are the length prefix of the MPI
       */
      expect(written[18]).to.equal(1);
      expect(written[19]).to.equal(2);
      expect(written[20]).to.equal(3);
    } finally {
      openpgp.config.v6Keys = originalv6KeysSetting;
    }
  });

  it('Writing and encryption of a secret key packet (CFB)', async function() {
    const rsa = openpgp.enums.publicKey.rsaEncryptSign;
    const { privateParams, publicParams } = await crypto.generateParams(rsa, 1024, 65537);
    const secretKeyPacket = new openpgp.SecretKeyPacket();
    secretKeyPacket.privateParams = privateParams;
    secretKeyPacket.publicParams = publicParams;
    secretKeyPacket.algorithm = openpgp.enums.publicKey.rsaSign;
    secretKeyPacket.isEncrypted = false;
    await secretKeyPacket.encrypt('hello', { ...openpgp.config, aeadProtect: false });
    expect(secretKeyPacket.s2kUsage).to.equal(254);

    const raw = new openpgp.PacketList();
    raw.push(secretKeyPacket);
    const packetList = await openpgp.PacketList.fromBinary(raw.write(), allAllowedPackets, openpgp.config);
    const secretKeyPacket2 = packetList[0];
    await secretKeyPacket2.decrypt('hello');
  });

  it('Writing and verification of a signature packet', function() {
    const rsa = openpgp.enums.publicKey.rsaEncryptSign;
    const key = new openpgp.SecretKeyPacket();

    return crypto.generateParams(rsa, 1024, 65537).then(async ({ privateParams, publicParams }) => {
      const testText = input.createSomeMessage();

      key.publicParams = publicParams;
      key.privateParams = privateParams;
      key.algorithm = openpgp.enums.publicKey.rsaSign;
      await key.computeFingerprintAndKeyID();

      const signed = new openpgp.PacketList();
      const literal = new openpgp.LiteralDataPacket();
      const signature = new openpgp.SignaturePacket();

      literal.setText(testText);

      signature.hashAlgorithm = openpgp.enums.hash.sha256;
      signature.publicKeyAlgorithm = openpgp.enums.publicKey.rsaSign;
      signature.signatureType = openpgp.enums.signature.text;

      return signature.sign(key, literal).then(async () => {

        signed.push(literal);
        signed.push(signature);

        const raw = signed.write();

        const signed2 = new openpgp.PacketList();
        await signed2.read(raw, allAllowedPackets);
        signed2.push(...await stream.readToEnd(signed2.stream, arr => arr));

        await Promise.all([
          signed2[1].verify(key, openpgp.enums.signature.text, signed2[0]),
          stream.readToEnd(signed2[0].getBytes())
        ]);
      });
    });
  });

  describe('PacketList parsing', function () {
    it('Ignores unknown packet version with `config.ignoreUnsupportedPackets` enabled', async function() {
      const armoredSignature = `-----BEGIN PGP SIGNATURE-----

iQFKBAEBCgA0FiEEdOyNPagqedqiXfEMa6Ve2Dq64bsFAlszXwQWHHRlc3Qtd2tk
QG1ldGFjb2RlLmJpegAKCRBrpV7YOrrhuw1PB/9KhFRR/M3OR6NmIent6ri1ekWn
vlcnVqj6N4Xqi1ahRVw19/Jx36mGyijxNwqqGrziqRiPCdT0pKfCfv7nXQf2Up1Z
LoR1StqpBMSDQfuF6JAJmJuB9T+mPQO8wYeUp+O63vQnm5CgqyoRlIoqX8MN6GTY
xK5PdTRjw6IEIGr9uLgSoUwTd0ECY1F9ptyuLGD5ET5ZtyUenQSbX+cw5WCGLFzi
7TwKTY+kGQpkwDJKZJSGpoP7ob6xdDfZx6dHV6IfIJg8/F9gtAXFp8uE51L90cV2
kePFjAnu9cpynKXu3usf8+FuBw2zLsg1Id1n7ttxoAte416KjBN9lFBt8mcu
=wEIR
-----END PGP SIGNATURE-----`;

      const { packets: [signaturePacket] } = await openpgp.readSignature({ armoredSignature });
      const packets = new openpgp.PacketList();
      signaturePacket.signatureData[0] = 1;
      packets.push(signaturePacket);
      const bytes = packets.write();
      const parsed = await openpgp.PacketList.fromBinary(bytes, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: true });
      expect(parsed.length).to.equal(1);
      expect(parsed[0].tag).to.equal(openpgp.enums.packet.signature);
    });

    it('Throws on unknown packet version with `config.ignoreUnsupportedPackets` disabled', async function() {
      const armoredSignature = `-----BEGIN PGP SIGNATURE-----

iQFKBAEBCgA0FiEEdOyNPagqedqiXfEMa6Ve2Dq64bsFAlszXwQWHHRlc3Qtd2tk
QG1ldGFjb2RlLmJpegAKCRBrpV7YOrrhuw1PB/9KhFRR/M3OR6NmIent6ri1ekWn
vlcnVqj6N4Xqi1ahRVw19/Jx36mGyijxNwqqGrziqRiPCdT0pKfCfv7nXQf2Up1Z
LoR1StqpBMSDQfuF6JAJmJuB9T+mPQO8wYeUp+O63vQnm5CgqyoRlIoqX8MN6GTY
xK5PdTRjw6IEIGr9uLgSoUwTd0ECY1F9ptyuLGD5ET5ZtyUenQSbX+cw5WCGLFzi
7TwKTY+kGQpkwDJKZJSGpoP7ob6xdDfZx6dHV6IfIJg8/F9gtAXFp8uE51L90cV2
kePFjAnu9cpynKXu3usf8+FuBw2zLsg1Id1n7ttxoAte416KjBN9lFBt8mcu
=wEIR
-----END PGP SIGNATURE-----`;

      const { packets: [signaturePacket] } = await openpgp.readSignature({ armoredSignature });
      const packets = new openpgp.PacketList();
      signaturePacket.signatureData[0] = 1;
      packets.push(signaturePacket);
      const bytes = packets.write();
      await expect(
        openpgp.PacketList.fromBinary(bytes, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: false })
      ).to.be.rejectedWith(/Version 1 of the signature packet is unsupported/);
    });

    it('Ignores unknown signature algorithm only with `config.ignoreUnsupportedPackets` enabled', async function() {
      const binarySignature = util.hexToUint8Array('c2750401630a00060502628b8e2200210910f30ddfc2310b3560162104b9b0045c1930f842cb245566f30ddfc2310b35602ded0100bd69fe6a9f52499cd8b2fd2493dae91c997979890df4467cf31b197901590ff10100ead4c671487535b718a8428c8e6099e3873a41610aad9fcdaa06f6df5f404002');

      const parsed = await openpgp.PacketList.fromBinary(binarySignature, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: true });
      expect(parsed.length).to.equal(1);
      expect(parsed[0]).instanceOf(openpgp.UnparseablePacket);
      expect(parsed[0].tag).to.equal(openpgp.enums.packet.signature);

      await expect(
        openpgp.PacketList.fromBinary(binarySignature, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: false })
      ).to.be.rejectedWith(/Unknown signature algorithm/);
    });

    it('Ignores unknown key algorithm only with `config.ignoreUnsupportedPackets` enabled', async function() {
      const binaryKey = util.hexToUint8Array('c55804628b944e63092b06010401da470f01010740d01ab8619b6dc6a36da5bff62ff416a974900f5a8c74d1bd1760d717d0aad8d50000ff516f8e3190aa5b394597655d7c32e16392e638da0e2a869fb7b1f429d9de263d1062cd0f3c7465737440746573742e636f6d3ec28c0410160a001d0502628b944e040b0907080315080a0416000201021901021b03021e01002109104803e40df201fa5b16210496dc42e91cc585e2f5e331644803e40df201fa5b340b0100812c47b60fa509e12e329fc37cc9c437cc6a6500915caa03ad8703db849846f900ff571b9a0d9e1dcc087d9fae04ec2906e60ef40ca02a387eb07ce1c37bedeecd0a');

      const parsed = await openpgp.PacketList.fromBinary(binaryKey, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: true });
      expect(parsed.length).to.equal(3);
      expect(parsed[0]).instanceOf(openpgp.UnparseablePacket);
      expect(parsed[0].tag).to.equal(openpgp.enums.packet.secretKey);

      await expect(
        openpgp.PacketList.fromBinary(binaryKey, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: false })
      ).to.be.rejectedWith(/Unknown public key encryption algorithm/);
    });

    it('Ignores unknown PKESK algorithm only with `config.ignoreUnsupportedPackets` enabled', async function() {
      const binaryMessage = util.hexToUint8Array('c15e03c6a6737124ef0f5e63010740282956b4db64ea79e1b4b8e5c528241b5e1cf40b2f5df2a619692755d532353d30a8e044e7c96f51741c73e6c5c8f73db08daf66e49240afe90c9b50705d51e71ec2e7630c5bd86b002e1f6dbd638f61e2d23501830d9bb3711c66963363a6e5f8d9294210a0cd194174c3caa3f29865d33c6be4c09b437f906ca8d35e666f3ef53fd22e0d8ceade');

      const parsed = await openpgp.PacketList.fromBinary(binaryMessage, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: true });
      expect(parsed.length).to.equal(2);
      expect(parsed[0]).instanceOf(openpgp.UnparseablePacket);
      expect(parsed[0].tag).to.equal(openpgp.enums.packet.publicKeyEncryptedSessionKey);

      await expect(
        openpgp.PacketList.fromBinary(binaryMessage, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: false })
      ).to.be.rejectedWith(/Unknown public key encryption algorithm/);
    });


    it('Throws on disallowed packet even with tolerant mode enabled', async function() {
      const packets = new openpgp.PacketList();
      packets.push(new openpgp.LiteralDataPacket());
      const bytes = packets.write();
      await expect(openpgp.PacketList.fromBinary(bytes, {}, { ...openpgp.config, ignoreUnsupportedPackets: false, ignoreMalformedPackets: false })).to.be.rejectedWith(/Packet not allowed in this context/);
      await expect(openpgp.PacketList.fromBinary(bytes, {}, { ...openpgp.config, ignoreUnsupportedPackets: true, ignoreMalformedPackets: true })).to.be.rejectedWith(/Packet not allowed in this context/);
    });

    it('Throws on parsing errors `config.ignoreMalformedPackets` disabled', async function () {
      const packets = new openpgp.PacketList();
      packets.push(openpgp.UserIDPacket.fromObject({ name:'test', email:'test@a.it' }));
      const bytes = packets.write();
      await expect(
        openpgp.PacketList.fromBinary(bytes, allAllowedPackets, { ...openpgp.config, maxUserIDLength: 2, ignoreMalformedPackets: false })
      ).to.be.rejectedWith(/User ID string is too long/);
      const parsed = await openpgp.PacketList.fromBinary(bytes, allAllowedPackets, { ...openpgp.config, maxUserIDLength: 2, ignoreMalformedPackets: true });
      expect(parsed.length).to.equal(1);
      expect(parsed[0].tag).to.equal(openpgp.enums.packet.userID);
    });

    it('Allow parsing of additional packets provided in `config.additionalAllowedPackets`', async function () {
      const packets = new openpgp.PacketList();
      packets.push(new openpgp.LiteralDataPacket());
      packets.push(openpgp.UserIDPacket.fromObject({ name:'test', email:'test@a.it' }));
      const bytes = packets.write();
      const allowedPackets = { [openpgp.enums.packet.literalData]: openpgp.LiteralDataPacket };
      await expect(openpgp.PacketList.fromBinary(bytes, allowedPackets)).to.be.rejectedWith(/Packet not allowed in this context: userID/);
      const parsed = await openpgp.PacketList.fromBinary(bytes, allowedPackets, { ...openpgp.config, additionalAllowedPackets: [openpgp.UserIDPacket] });
      expect(parsed.length).to.equal(1);
      expect(parsed[0].constructor.tag).to.equal(openpgp.enums.packet.literalData);
      const otherPackets = await stream.readToEnd(parsed.stream, _ => _);
      expect(otherPackets.length).to.equal(1);
      expect(otherPackets[0].constructor.tag).to.equal(openpgp.enums.packet.userID);
    });
  });
});
