'use strict'

const tls = require('tls')
const packet = require('..')

var response = null
var expected_length = 0

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

const encodedPacket = packet.streamEncode({
  type: 'query',
  id: getRandomInt(1, 65534),
  flags: packet.RECURSION_DESIRED,
  questions: [{
    type: 'A',
    name: 'google.com'
  }]
})

const context = tls.createSecureContext({
  secureProtocol: 'TLSv1_2_method'
})

const options = {
  port: 853,
  host: 'getdnsapi.net',
  secureContext: context
}

const client = tls.connect(options, () => {
  console.log('client connected')
  client.write(encodedPacket)
})

client.on('data', function (data) {
  console.log('Received response: %d bytes', data.byteLength)
  if (response == null) {
    if (data.byteLength > 1) {
      const plen = data.readUInt16BE(0)
      expected_length = plen
      if (plen < 12) {
        throw new Error('below DNS minimum packet length')
      }
      response = Buffer.from(data)
    }
  } else {
    response = Buffer.concat([response, data])
  }

  if (response.byteLength >= expected_length) {
    console.log(packet.streamDecode(response))
    client.destroy()
  }
})

client.on('end', () => {
  console.log('Connection ended')
})
