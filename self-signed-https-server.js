var https = require('https')
var pem = require('pem')
var ip = require("ip");

pem.createCertificate({ days: 20, selfSigned: true }, function (err, keys) {
  if (err) {
    throw err
  }
  https.createServer({ key: keys.serviceKey, cert: keys.certificate }, function (req, res) {

    res.end('o hai!')
  }).listen(443)
  console.log(`Self-Signed Server now is running on ${ip.address()}`)
})