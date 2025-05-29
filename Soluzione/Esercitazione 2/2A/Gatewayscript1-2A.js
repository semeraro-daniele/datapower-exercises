var hm = require('header-metadata');
var urlopen = require('urlopen');

// 1 Recupero del JWT dall'header Authorization
var authHeader = hm.current.get('Authorization');

// Controlla che l'header Authorization sia presente e nel formato corretto
if (!authHeader || !authHeader.startsWith('Bearer ')) {
    session.reject('Missing or invalid Authorization header');
    return;
}

// Estrae il token JWT rimuovendo il prefisso "Bearer "
var token = authHeader.substring('Bearer '.length);

// 2 Verifica del JWT tramite backend che espone JWKS (/protected)
var optionsValidate = {
    target: 'http://datapower:5001/protected',
    method: 'GET',
    headers: {
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/json'
    },
    timeout: 60
};

// Chiamata al backend per validare il token
urlopen.open(optionsValidate, function(err, response) {
    if (err) {
        session.reject('Error validating token: ' + err.toString());
        return;
    }

    // Se il token non è valido (es. 401 Unauthorized)
    if (response.statusCode !== 200) {
        response.readAsJSON(function(err, body) {
            var reason = (body && body.error) ? body.error : 'Invalid token';
            session.reject('JWT validation failed: ' + reason);
        });
        return;
    }

    // 3 Il token è valido → Estrae i dati e prepara il forwarding
    response.readAsJSON(function(err, data) {
        if (err) {
            session.reject('Error reading backend response: ' + err.toString());
            return;
        }

        var innerPayload = data.payload.payload;

        var optionsEcho = {
            target: 'http://datapower:5000/echo',
            method: 'GET',
            headers: {
                'X-User': innerPayload.sub || '', // Inietta il claim 'sub' come intestazione
                'X-Scopes': (innerPayload.scope || '').split(' ').join(' '), // Eventuale lista scope
                'Authorization': 'Bearer ' + token // Forwarda anche il token originale
            },
            timeout: 60
        };

        // 4 Forward della richiesta all’Echo backend
        urlopen.open(optionsEcho, function(err, responseEcho) {
            if (err) {
                session.reject('Error calling Echo backend: ' + err.toString());
                return;
            }

            if (responseEcho.statusCode !== 200) {
                session.reject('Echo backend returned status: ' + responseEcho.statusCode);
                return;
            }

            // Legge la risposta dell’echo server
            responseEcho.readAsJSON(function(err, echoData) {
                if (err) {
                    session.reject('Error reading Echo response: ' + err.toString());
                    return;
                }

                // Risposta finale al client con il messaggio e la risposta dell’echo
                session.output.write({
                    message: 'JWT validated and forwarded to Echo',
                    echoResponse: echoData
                });
            });
        });
    });
});