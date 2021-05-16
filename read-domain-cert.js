var https = require('https');
var spawn = require('child_process').spawn;
var host = '192.168.1.9'
var port = 443;

var options = {
    host: host,
    port: port,
    method: 'GET'
};

async function getCertificateInfo(cert) {
    return new Promise((resolve, reject) => {

        var infoObject = {},
            issuerElements = [],
            subjectElements = [];

        var openssl = spawn('openssl', ['x509', '-noout', '-issuer', '-subject', '-dates', '-nameopt', 'RFC2253']);

        var stderr = [];
        var stdout = [];

        openssl.stderr.on('data', stderr.push.bind(stderr));
        openssl.stdout.on('data', stdout.push.bind(stdout));

        openssl.on('close', function (code) {
            if (code !== 0) {
                var error = Buffer.concat(stderr).toString();
                // Callback and return array
                return reject(error);
            }

            var data = Buffer.concat(stdout).toString();

            // Put each line into an array
            var lineArray = data.split('\n');
            // Filter out empty ones
            lineArray = lineArray.filter(function (n) { return n !== undefined && n !== '' });

            // Check if output is exact four lines
            if (lineArray.length !== 4) {
                return reject('Couldn\'t read certificate');
            }

            /* Construct infoObject */

            // Certificate
            infoObject.certificate = cert;

            // Issuer
            infoObject.issuer = {};
            // Split by "," separator
            issuerElements = lineArray[0].replace('issuer=', '').split(',');
            // For each elements
            for (var iI = 0; iI < issuerElements.length; iI++) {
                // Split keys and values by "=" separator
                var issuerKeyValue = issuerElements[iI].split('=');
                infoObject.issuer[issuerKeyValue[0].trim()] = issuerKeyValue[1];
            }

            // Subject
            infoObject.subject = {};
            // Split by "," separator
            subjectElements = lineArray[1].replace('subject=', '').split(',');
            // For each elements
            for (var iS = 0; iS < subjectElements.length; iS++) {
                // Split keys and values by "=" separator
                var subjectKeyValue = subjectElements[iS].split('=');
                infoObject.subject[subjectKeyValue[0].trim()] = subjectKeyValue[1];
            }

            // Dates
            infoObject.validFrom = new Date(lineArray[2].split('=')[1]);
            infoObject.validTo = new Date(lineArray[3].split('=')[1]);

            // Check if "to" date is in the past => certificate expired
            if (infoObject.validTo < new Date()) {
                infoObject.expiredDays = Math.round(Math.abs((Date.now() - infoObject.validTo.getTime()) / (24 * 60 * 60 * 1000)));
                infoObject.remainingDays = 0;
            } else {
                infoObject.remainingDays = Math.round(Math.abs((Date.now() - infoObject.validTo.getTime()) / (24 * 60 * 60 * 1000)));
            }

            // Callback and return array
            return resolve(infoObject);
        });
        openssl.stdin.write(cert);
        openssl.stdin.end();
    });
}

async function getCertificateChain(host, port) {
    return new Promise((resolve, reject) => {

        var stdout = '',
            stderr = '';

        var openssl = spawn('openssl', ['s_client', '-showcerts', '-connect', host + ':' + port, '-servername', host]);

        // Clear timeout when execution was successful
        openssl.on('exit', async function (code) {
            clearTimeout(timeoutTimer);

            // Check if exit code is null
            if (code === null) {
                // ... probably killed due to time out
                return reject('Time out while trying to extract certificate chain for ' + host + ':' + port);
            }

            if (stderr) {
                // Search for possible errors in stderr
                var errorRegexp = /(Connection refused)|(Can't assign requested address)|(gethostbyname failure)|(getaddrinfo: nodename)|(Name or service not known)/;
                var regexTester = errorRegexp.test(stderr);

                // If match, raise error
                if (regexTester) {
                    // Callback and return array
                    return reject(stderr.toString().replace(/^\s+|\s+$/g, ''))
                }
            }

            if (stdout) {
                // Search for certificate in stdout
                var matches = stdout.match(/s:([\s\S.]*?)i:[\s\S.]*?-----BEGIN CERTIFICATE-----([\s\S.]*?)-----END CERTIFICATE-----/g);

                try {
                    var data = [];
                    for (var match of matches) {
                        var certificate = Object()
                        var lines = match.split('\n');
                        // Remove "issuer" line (c:/C)
                        var issuer = lines.splice(1, 1);
                        // Remove "subject" line in separate variable
                        var subject = lines.splice(0, 1);
                        var base64_cert = lines.join('')
                        base64_cert = base64_cert.replace('-----BEGIN CERTIFICATE-----', '')
                        base64_cert = base64_cert.replace('-----END CERTIFICATE-----', '')

                        certificate['issuer'] = issuer
                        certificate['subject'] = subject
                        certificate['base64_cert'] = base64_cert
                        certificate['info'] = await getCertificateInfo(fromBase64ToDERX509Certificate(base64_cert)).catch((error) => console.error(error))

                        data.push(certificate);
                    }
                } catch (e) {
                    // ... otherwise raise error
                    return reject('Couldn\'t extract certificate chain for ' + host + ':' + port);
                }
            }

            // ... callback and return certificate chain
            return resolve(data);
        });

        // Catch stderr and search for possible errors
        openssl.stderr.on('data', function (out) {
            stderr += out.toString();
        });

        openssl.stdout.on('data', function (out) {
            stdout += out.toString();
        });

        // End stdin (otherwise it'll run indefinitely)
        openssl.stdin.end();

        // Timeout function to kill in case of errors
        var timeoutTimer = setTimeout(function () {
            openssl.kill();
        }, 5000);
    });
}

function fromBase64ToDERX509Certificate(cert) {
    var prefix = '-----BEGIN CERTIFICATE-----\n';
    var postfix = '-----END CERTIFICATE-----';
    return prefix + cert.match(/.{0,64}/g).join('\n') + postfix;
}

function connectToServer(options) {
    getCertificateChain(host, `${port}`).then((chain) => {
        chain.forEach(element => {
            console.log(element);
            console.log("============================ Next Certificate ============================");
        });
    });

    // var req = https.request(options, function (res) {
    //     var leaf_cert = res.connection.getPeerCertificate()
    //     // console.log(leaf_cert);
    //     var next_cert_URI = getNextCrtURI(leaf_cert)
    //     return resolve(next_cert_URI)
    // });
    // req.end();
}

connectToServer(options);