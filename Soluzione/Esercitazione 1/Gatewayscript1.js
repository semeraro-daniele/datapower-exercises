var hm = require('header-metadata'); // Per leggere/mettere gli header HTTP
var urlopen = require('urlopen'); // Per effettuare chiamate HTTP verso l’esterno
var querystring = require('querystring'); // Per parsare i parametri x-www-form-urlencoded

var now = Math.floor(Date.now() / 1000);

// Legge il body della richiesta HTTP in arrivo
session.input.readAsBuffer(function(err, buffer) {
    if (err) {
        session.reject('Error reading input body: ' + err);
        return;
    }

    // Parsing del body da buffer a stringa UTF-8 e poi a oggetto chiave/valore
    var bodyStr = buffer.toString('utf-8');
    var bodyParams = querystring.parse(bodyStr);
    var grantType = bodyParams['grant_type'];

    // Se manca il parametro grant_type, la richiesta viene rifiutata
    if (!grantType) {
        session.reject('Missing grant_type parameter');
        return;
    }

    var validatePayload;

    // 1. Flusso Password Grant
    if (grantType === 'password') {
        // Estrae header Authorization, atteso in formato "Basic base64(user:pass)"
        var authHeader = hm.current.get('Authorization');
        if (!authHeader || !authHeader.startsWith('Basic ')) {
            session.reject('Invalid or missing Authorization header');
            return;
        }

        // Decodifica le credenziali base64 → "user:pass"
        var encodedCredentials = authHeader.substring(6);
        var decodedCredentials = Buffer.from(encodedCredentials, 'base64').toString('utf-8');
        var credentials = decodedCredentials.split(':');

        // Controlla che ci siano esattamente username e password
        if (credentials.length !== 2) {
            session.reject('Malformed credentials');
            return;
        }

        // Prepara il payload JSON per la chiamata al backend di validazione
        validatePayload = JSON.stringify({
            username: credentials[0],
            password: credentials[1]
        });

        // 2. Flusso Client Credentials Grant
    } else if (grantType === 'client_credentials') {
        // Recupera i parametri
        var clientId = bodyParams['client_id'];
        var clientSecret = bodyParams['client_secret'];

        // Controlli minimi di validità
        if (!clientId || typeof clientId !== 'string' || clientId.trim() === '') {
            session.reject('Missing or invalid client_id');
            return;
        }

        if (!clientSecret || typeof clientSecret !== 'string' || clientSecret.trim() === '') {
            session.reject('Missing or invalid client_secret');
            return;
        }

        // Prepara il payload JSON per la validazione
        validatePayload = JSON.stringify({
            client_id: clientId,
            client_secret: clientSecret
        });

        // 3. Grant Type non supportato
    } else {
        session.reject('Unsupported grant_type');
        return;
    }

    // 4. Chiamata al backend per la validazione delle credenziali
    var validateOptions = {
        target: 'http://datapower:5002/validate',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        data: validatePayload
    };

    // Effettua la chiamata HTTP al backend
    urlopen.open(validateOptions, function(err, response) {
        if (err) {
            session.reject('Internal error: ' + err.toString());
            return;
        }

        // Se il backend risponde con errore (es. 401), si restituisce errore al client
        if (response.statusCode !== 200) {
            session.output.write({
                err: 'Authentication failed',
                status: response.statusCode
            });
            return;
        }

        // Legge la risposta JSON del backend
        response.readAsJSON(function(err, userInfo) {
            if (err) {
                session.reject('Error parsing response from backend');
                return;
            }

            // Se le credenziali non sono valide, errore
            if (!userInfo.valid) {
                session.output.write({
                    err: 'Invalid credentials'
                });
                return;
            }

            // 5. Costruzione JWT

            // Header del JWT (algoritmo, tipo, key id)
            var jwtHeader = {
                alg: 'RS256',
                typ: 'JWT',
                kid: 'test-key-1'
            };

            // Payload con i claim standard: issuer, subject, scadenza, scope
            var jwtPayload = {
                iss: 'http://datapower:8080', // Identifica chi ha emesso il token
                sub: userInfo.subject, // Chi è il soggetto (utente o client)
                exp: now + 3600, // Scadenza a 1 ora dal timestamp attuale
                scope: userInfo.scopes.join(' ') // Scope come stringa separata da spazi
            };

            var signInput = {
                header: jwtHeader,
                payload: jwtPayload
            };

            // Output JSON da firmare
            session.output.write(JSON.stringify(signInput));
        });
    });
});