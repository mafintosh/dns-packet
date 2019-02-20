'use strict'

exports.toString = function (type) {
  switch (type) {
    case 3: return 'NSID'
    case 5: return 'DAU'
    case 6: return 'DHU'
    case 7: return 'N3U'
    case 8: return 'ECS'
    case 9: return 'EXPIRE'
    case 10: return 'COOKIE'
    case 11: return 'KEEP-ALIVE'
    case 12: return 'PADDING'
    case 13: return 'CHAIN'
    case 14: return 'KEY-TAG'
  }
  return 'UNKNOWN_' + type
}

exports.toCode = function (name) {
  if (typeof name === 'number') {
    return name
  }
  switch (name.toUpperCase()) {
    case 'NSID': return 3
    case 'DAU': return 5
    case 'DHU': return 6
    case 'N3U': return 7
    case 'ECS': return 8
    case 'EXPIRE': return 9
    case 'COOKIE': return 10
    case 'KEEPALIVE': return 11
    case 'KEEP-ALIVE': return 11
    case 'PADDING': return 12
    case 'CHAIN': return 13
    case 'KEY-TAG': return 14
    case 'KEYTAG': return 14
  }
  if (name.toUpperCase().startsWith('UNKNOWN_')) return parseInt(name.slice(8))
  return 0
}
