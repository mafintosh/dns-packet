'use strict'

const typeToString = {}
const typeToNumber = {}

function toString (type) {
  return typeToString[type] || ('UNKNOWN_' + type)
}

function toType (name) {
  if (typeof name === 'number') return name
  const upper = name.toUpperCase()
  if (typeToNumber[upper] !== undefined) return typeToNumber[upper]
  if (upper.startsWith('UNKNOWN_')) return parseInt(upper.slice(8))
  return 0
}

// Populate lookup maps
const types = [
  [1, 'A'],
  [10, 'NULL'],
  [28, 'AAAA'],
  [18, 'AFSDB'],
  [42, 'APL'],
  [257, 'CAA'],
  [60, 'CDNSKEY'],
  [59, 'CDS'],
  [37, 'CERT'],
  [5, 'CNAME'],
  [49, 'DHCID'],
  [32769, 'DLV'],
  [39, 'DNAME'],
  [48, 'DNSKEY'],
  [43, 'DS'],
  [55, 'HIP'],
  [13, 'HINFO'],
  [45, 'IPSECKEY'],
  [25, 'KEY'],
  [36, 'KX'],
  [29, 'LOC'],
  [15, 'MX'],
  [35, 'NAPTR'],
  [2, 'NS'],
  [47, 'NSEC'],
  [50, 'NSEC3'],
  [51, 'NSEC3PARAM'],
  [12, 'PTR'],
  [46, 'RRSIG'],
  [17, 'RP'],
  [24, 'SIG'],
  [6, 'SOA'],
  [99, 'SPF'],
  [33, 'SRV'],
  [44, 'SSHFP'],
  [32768, 'TA'],
  [249, 'TKEY'],
  [52, 'TLSA'],
  [250, 'TSIG'],
  [16, 'TXT'],
  [252, 'AXFR'],
  [251, 'IXFR'],
  [41, 'OPT'],
  [255, 'ANY']
]

for (const [num, str] of types) {
  typeToString[num] = str
  typeToNumber[str] = num
}
// '*' is an alias for ANY
typeToNumber['*'] = 255

exports.toString = toString
exports.toType = toType
