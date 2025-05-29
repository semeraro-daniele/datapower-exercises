var hm = require('header-metadata');
var querystring = require('querystring');

var now = Math.floor(Date.now() / 1000);

function base64urlEncode(obj) {
    var json = JSON.stringify(obj);
    var b64 = Buffer.from(json).toString('base64');
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

session.input.readAsBuffer(function(err, buffer) {
    if (err) {
        session.reject('Error reading input body: ' + err);
        return;
    }

    // Prepara header JWT
    var jwtHeader = {
        alg: 'RS256',
        typ: 'JWT',
        kid: 'test-key-1'
    };

    // Prepara payload JWT con subject fisso "gateway-user"
    var jwtPayload = {
        sub: 'gateway-user',
        iat: now,
        exp: now + 3600
    };

    // Codifica header e payload in base64url
    var encodedHeader = base64urlEncode(jwtHeader);
    var encodedPayload = base64urlEncode(jwtPayload);

    // JWT "da firmare" (header.payload)
    var jwtToSign = encodedHeader + '.' + encodedPayload;

	// Output da firmare
    session.output.write(jwtToSign);
});