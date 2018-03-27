
'use strict'

/*
 * Sample code to make DNS over HTTPS request using POST
 * AUTHOR: Tom Pusateri <pusateri@bangj.com>
 * DATE: March 17, 2018
 * LICENSE: MIT
 */

const packet = require('..')
const https = require('https')

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

const encodedPacket = packet.encode({
  type: 'query',
  id: getRandomInt(1, 65534),
  flags: packet.RECURSION_DESIRED,
  questions: [{
    type: 'A',
    name: 'google.com'
  }]
})

const options = {
  hostname: 'dns.google.com',
  port: 443,
  path: '/experimental',
  method: 'POST',
  headers: {
    'Content-Type': 'application/dns-udpwireformat',
    'Content-Length': Buffer.byteLength(encodedPacket)
  }
}

const request = https.request(options, (response) => {
  console.log('statusCode:', response.statusCode)
  console.log('headers:', response.headers)

  response.on('data', (d) => {
    console.log(packet.decode(d))
  })
})

request.on('error', (e) => {
  console.error(e)
})
request.write(encodedPacket)
request.end()

