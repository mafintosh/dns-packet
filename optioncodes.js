'use strict'

exports.toString = function (type) {
  switch (type) {
    // return the literals from the list at
    // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
    case 0: return 'Reserved 0'
    case 1: return 'LLQ'
    case 2: return 'UL'
    case 3: return 'NSID'
    case 4: return 'Reserved 4'
    case 5: return 'DAU'
    case 6: return 'DHU'
    case 7: return 'N3U'
    case 8: return 'edns-client-subnet'
    case 9: return 'EDNS EXPIRE'
    case 10: return 'COOKIE'
    case 11: return 'edns-tcp-keepalive'
    case 12: return 'Padding'
    case 13: return 'CHAIN'
    case 14: return 'edns-key-tag'
    case 26946: return 'DeviceID'
    case 65535: return 'Reserved for future expansion'
  }
  if (type < 0) {
    return `Invalid ${type}`
  }
  if (type < 65001) {
    return `Unassigned ${type}`
  }
  return `Reserved for Local/Experimental Use ${type}`
}

exports.toCode = function (name) {
  if (typeof name === 'number') {
    return name
  }
  switch (name.toUpperCase()) {
    case 'RESERVED 0': return 0
    case 'LLQ': return 1
    case 'UL': return 2
    case 'NSID': return 3
    case 'RESERVED 4': return 4
    case 'DAU': return 5
    case 'DHU': return 6
    case 'N3U': return 7
    case 'EDNS-CLIENT-SUBNET': return 8
    case 'CLIENT-SUBNET': return 8 // drop "EDNS-"
    case 'EDNS EXPIRE': return 9
    case 'EXPIRE': return 9 // drop "EDNS "
    case 'COOKIE': return 10
    case 'EDNS-TCP-KEEPALIVE': return 11
    case 'TCP-KEEPALIVE': return 11 // drop "EDNS-"
    case 'PADDING': return 12
    case 'CHAIN': return 13
    case 'EDNS-KEY-TAG': return 14
    case 'KEY-TAG': return 14 // drop "EDNS-"
    case 'DEVICEID': return 26946
    case 'RESERVED FOR FUTURE EXPANSION': return 65535
  }
  const m = name.match(/ (\d+)$/)
  if (m) {
    return parseInt(m[1], 10)
  }
  return -1
}
