'use strict'

const codeToString = {}
const stringToCode = {}

function toString (opcode) {
  return codeToString[opcode] || ('OPCODE_' + opcode)
}

function toOpcode (code) {
  if (typeof code === 'number') return code
  const upper = code.toUpperCase()
  if (stringToCode[upper] !== undefined) return stringToCode[upper]
  return 0
}

const codes = [
  [0, 'QUERY'],
  [1, 'IQUERY'],
  [2, 'STATUS'],
  [3, 'OPCODE_3'],
  [4, 'NOTIFY'],
  [5, 'UPDATE'],
  [6, 'OPCODE_6'],
  [7, 'OPCODE_7'],
  [8, 'OPCODE_8'],
  [9, 'OPCODE_9'],
  [10, 'OPCODE_10'],
  [11, 'OPCODE_11'],
  [12, 'OPCODE_12'],
  [13, 'OPCODE_13'],
  [14, 'OPCODE_14'],
  [15, 'OPCODE_15']
]

for (const [num, str] of codes) {
  codeToString[num] = str
  stringToCode[str] = num
}

exports.toString = toString
exports.toOpcode = toOpcode
