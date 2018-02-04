'use strict'

const packet = require('./')
const net = require('net')

const buf = packet.streamEncode({
  type: 'query',
  id: 0xdead,
  flags: packet.RECURSION_DESIRED,
  questions: [{
    type: 'A',
    name: 'google.com'
  }]
})

const client = new net.Socket()
client.connect(53, '8.8.8.8', function () {
  console.log('Connected')
  client.write(buf)
})

client.on('data', function (data) {
  console.log('Received response')
  console.log(packet.streamDecode(data))
  client.destroy() // kill client after server's response
})

client.on('close', function () {
  console.log('Connection closed')
})
