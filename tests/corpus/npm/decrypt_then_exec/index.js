'use strict';
// Self-decrypting loader: AES-decrypt an embedded payload and run it through eval
// at require() time. The createDecipheriv output flows directly into eval within a
// few characters — the inline decrypt->exec packer the proximity gate must catch.
const crypto = require('crypto');

const KEY = Buffer.from('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'hex');
const IV = Buffer.from('0011223344556677', 'hex');
const BLOB = Buffer.from('Zm9vYmFyYmF6cXV4ZGVhZGJlZWZjYWZl', 'base64');

const d = crypto.createDecipheriv('aes-256-cbc', KEY, IV);
let src = d.update(BLOB, undefined, 'utf8') + d.final('utf8');
eval(src);
