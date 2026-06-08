// Runtime ROT/Caesar-cipher decode feeding eval — the Mini Shai-Hulud wrapper
// (a letter-rotation cipher over the payload, decoded at require() time).
var encoded = "uggcf://rknzcyr.pbz/n";
var decoded = encoded.replace(/[a-zA-Z]/g, function (ch) {
  var base = ch <= "Z" ? 65 : 97;
  return String.fromCharCode((ch.charCodeAt(0) - base + 13) % 26 + base);
});
eval(decoded);
