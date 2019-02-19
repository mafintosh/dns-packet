'use strict'

exports.toString = function (type) {
  switch (type) {
    case 8: return 'ECS'
    case 12: return 'PADDING'
  }
  return 'UNKNOWN_' + type
}

exports.toCode = function (name) {
  if (typeof name === 'number') {
    return name
  }
  switch (name.toUpperCase()) {
    case 'ECS': return 8
    case 'PADDING': return 12
  }
  if (name.toUpperCase().startsWith('UNKNOWN_')) return parseInt(name.slice(8))
  return 0
}
