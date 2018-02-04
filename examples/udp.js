'use strict'

const packet = require('./')
const dgram = require('dgram')

const socket = dgram.createSocket('udp4')

const buf = packet.encode({
  type: 'query',
  id: 1,
  flags: packet.RECURSION_DESIRED,
  questions: [{
    type: 'A',
    name: 'google.com'
  }]
})

socket.on('message', function (message, rinfo) {
  console.log(rinfo)
  console.log(packet.decode(message)) // prints out a response from google dns
})

socket.send(buf, 0, buf.length, 53, '8.8.8.8')
