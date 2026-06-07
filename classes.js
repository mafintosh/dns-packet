'use strict'

const codeToString = {}
const stringToCode = {}

function toString (klass) {
  return codeToString[klass] || ('UNKNOWN_' + klass)
}

function toClass (name) {
  if (typeof name === 'number') return name
  const upper = name.toUpperCase()
  if (stringToCode[upper] !== undefined) return stringToCode[upper]
  return 0
}

const classes = [
  [1, 'IN'],
  [2, 'CS'],
  [3, 'CH'],
  [4, 'HS'],
  [255, 'ANY']
]

for (const [num, str] of classes) {
  codeToString[num] = str
  stringToCode[str] = num
}

exports.toString = toString
exports.toClass = toClass
