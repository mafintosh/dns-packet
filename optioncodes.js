'use strict'

const codeToString = {}
const stringToCode = {}

function toString (type) {
  if (type < 0) return null
  return codeToString[type] || ('OPTION_' + type)
}

function toCode (name) {
  if (typeof name === 'number') {
    return name
  }
  if (!name) {
    return -1
  }
  const upper = name.toUpperCase()
  if (stringToCode[upper] !== undefined) return stringToCode[upper]
  const m = name.match(/_(\d+)$/)
  if (m) {
    return parseInt(m[1], 10)
  }
  return -1
}

const codes = [
  [1, 'LLQ'],
  [2, 'UL'],
  [3, 'NSID'],
  [5, 'DAU'],
  [6, 'DHU'],
  [7, 'N3U'],
  [8, 'CLIENT_SUBNET'],
  [9, 'EXPIRE'],
  [10, 'COOKIE'],
  [11, 'TCP_KEEPALIVE'],
  [12, 'PADDING'],
  [13, 'CHAIN'],
  [14, 'KEY_TAG'],
  [26946, 'DEVICEID']
]

for (const [num, str] of codes) {
  codeToString[num] = str
  stringToCode[str] = num
}
// Extra string -> code mappings for numeric option codes
stringToCode['OPTION_0'] = 0
stringToCode['OPTION_4'] = 4
stringToCode['OPTION_65535'] = 65535

exports.toString = toString
exports.toCode = toCode
