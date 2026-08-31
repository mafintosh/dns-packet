'use strict'

const codeToString = {}
const stringToCode = {}

function toString (rcode) {
  return codeToString[rcode] || ('RCODE_' + rcode)
}

function toRcode (code) {
  if (typeof code === 'number') return code
  const upper = code.toUpperCase()
  if (stringToCode[upper] !== undefined) return stringToCode[upper]
  return 0
}

const codes = [
  [0, 'NOERROR'],
  [1, 'FORMERR'],
  [2, 'SERVFAIL'],
  [3, 'NXDOMAIN'],
  [4, 'NOTIMP'],
  [5, 'REFUSED'],
  [6, 'YXDOMAIN'],
  [7, 'YXRRSET'],
  [8, 'NXRRSET'],
  [9, 'NOTAUTH'],
  [10, 'NOTZONE'],
  [11, 'RCODE_11'],
  [12, 'RCODE_12'],
  [13, 'RCODE_13'],
  [14, 'RCODE_14'],
  [15, 'RCODE_15']
]

for (const [num, str] of codes) {
  codeToString[num] = str
  stringToCode[str] = num
}

exports.toString = toString
exports.toRcode = toRcode
