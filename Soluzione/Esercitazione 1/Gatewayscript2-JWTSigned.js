var hm = require('header-metadata');

session.input.readAsBuffer(function(err, response) {
    if (err) {
        session.reject('Errore lettura JWT: ' + err);
        return;
    }

    var signedJwt = response.toString('utf-8');

    var jwtResponse = {
        access_token: signedJwt,
        token_type: 'Bearer',
        expires_in: 3600
    };

    hm.response.set('Content-Type', 'application/json');
    session.output.write(JSON.stringify(jwtResponse));
});
