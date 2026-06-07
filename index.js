'use strict'

const Buffer = require('buffer').Buffer
const types = require('./types')
const rcodes = require('./rcodes')
const opcodes = require('./opcodes')
const classes = require('./classes')
const optioncodes = require('./optioncodes')
const ip = require('@leichtgewicht/ip-codec')

const QUERY_FLAG = 0
const RESPONSE_FLAG = 1 << 15
const FLUSH_MASK = 1 << 15
const NOT_FLUSH_MASK = ~FLUSH_MASK
const QU_MASK = 1 << 15
const NOT_QU_MASK = ~QU_MASK

// Pre-computed common type numbers
const TYPE_A = 1
const TYPE_NS = 2
const TYPE_CNAME = 5
const TYPE_SOA = 6
const TYPE_PTR = 12
const TYPE_MX = 15
const TYPE_TXT = 16
const TYPE_AAAA = 28
const TYPE_SRV = 33
const TYPE_OPT = 41
const TYPE_ANY = 255

// Helper: fast byteLength for ASCII strings
function byteLengthAscii(s) {
  const len = s.length
  for (let i = 0; i < len; i++) {
    if (s.charCodeAt(i) > 127) {
      return Buffer.byteLength(s)
    }
  }
  return len
}

// Helper: check if string is pure ASCII and write it to buffer
// Returns number of bytes written (same as string length for ASCII)
function asciiWrite(str, buf, offset) {
  const len = str.length
  let isAscii = true
  for (let i = 0; i < len; i++) {
    if (str.charCodeAt(i) > 127) {
      isAscii = false
      break
    }
  }
  if (isAscii) {
    for (let i = 0; i < len; i++) {
      buf[offset + i] = str.charCodeAt(i)
    }
    return len
  }
  return buf.write(str, offset)
}

// Helper: check if buffer region is pure ASCII and convert to string
function asciiToString(buf, offset, len) {
  let isAscii = true
  for (let i = 0; i < len; i++) {
    if (buf[offset + i] > 127) {
      isAscii = false
      break
    }
  }
  if (isAscii) {
    let s = ''
    for (let i = 0; i < len; i++) {
      s += String.fromCharCode(buf[offset + i])
    }
    return s
  }
  return buf.toString('utf-8', offset, offset + len)
}

const name = exports.name = {}

name.encode = function (str, buf, offset, opts) {
  const mail = opts ? opts.mail : false
  if (!buf) buf = Buffer.alloc(name.encodingLength(str))
  if (!offset) offset = 0
  const oldOffset = offset

  // strip leading and trailing .
  let n = str
  let start = 0
  let end = n.length
  if (end > 0 && n.charCodeAt(0) === 0x2E) start = 1
  if (end > start && n.charCodeAt(end - 1) === 0x2E) end--
  n = start > 0 || end < str.length ? n.substring(start, end) : n

  if (n.length) {
    if (mail) {
      let localPart = ''
      let pos = 0
      while (pos < n.length) {
        let dotPos = n.indexOf('.', pos)
        if (dotPos === -1) dotPos = n.length
        const label = n.substring(pos, dotPos)
        pos = dotPos + 1

        if (label.charCodeAt(label.length - 1) === 0x5C) {
          localPart += (localPart.length ? '.' : '') + label.slice(0, -1)
        } else if (localPart.length && !buf._nameLabels) {
          // First non-escaped label after escaped labels
          const combined = localPart + '.' + label
          const len = buf.write(combined, offset + 1)
          buf[offset] = len
          offset += len + 1
          localPart = ''
        } else {
          if (localPart.length) {
            const combined = localPart + '.' + label
            const len = buf.write(combined, offset + 1)
            buf[offset] = len
            offset += len + 1
            localPart = ''
          } else {
            const len = buf.write(label, offset + 1)
            buf[offset] = len
            offset += len + 1
          }
        }
      }
    } else {
      // Direct label iteration without split
      let pos = 0
      while (pos < n.length) {
        let dotPos = n.indexOf('.', pos)
        if (dotPos === -1) dotPos = n.length
        const label = n.substring(pos, dotPos)
        pos = dotPos + 1
        const len = asciiWrite(label, buf, offset + 1)
        buf[offset] = len
        offset += len + 1
      }
    }
  }

  buf[offset++] = 0

  name.encode.bytes = offset - oldOffset
  return buf
}

name.encode.bytes = 0

name.decode = function (buf, offset, opts) {
  if (!offset) offset = 0
  const mail = opts ? opts.mail : false

  let oldOffset = offset
  let totalLength = 0
  let consumedBytes = 0
  let jumped = false

  // Build result string directly to avoid array + join overhead
  let result = ''
  let firstLabel = true

  while (true) {
    if (offset >= buf.length) {
      throw new Error('Cannot decode name (buffer overflow)')
    }
    const len = buf[offset++]
    consumedBytes += jumped ? 0 : 1

    if (len === 0) {
      break
    } else if ((len & 0xc0) === 0) {
      if (offset + len > buf.length) {
        throw new Error('Cannot decode name (buffer overflow)')
      }
      totalLength += len + 1
      if (totalLength > 254) {
        throw new Error('Cannot decode name (name too long)')
      }
      let label = asciiToString(buf, offset, len)
      if (mail) {
        label = label.replace(/\./g, '\\.')
      }
      if (firstLabel) {
        result = label
        firstLabel = false
      } else {
        result += '.' + label
      }
      offset += len
      consumedBytes += jumped ? 0 : len
    } else if ((len & 0xc0) === 0xc0) {
      if (offset + 1 > buf.length) {
        throw new Error('Cannot decode name (buffer overflow)')
      }
      const jumpOffset = ((buf[offset - 1] << 8) | buf[offset - 1 + 1]) - 0xc000
      if (jumpOffset >= oldOffset) {
        // Allow only pointers to prior data. RFC 1035, section 4.1.4 states:
        // "[...] an entire domain name or a list of labels at the end of a domain name
        // is replaced with a pointer to a prior occurance (sic) of the same name."
        throw new Error('Cannot decode name (bad pointer)')
      }
      offset = jumpOffset
      oldOffset = jumpOffset
      consumedBytes += jumped ? 0 : 1
      jumped = true
    } else {
      throw new Error('Cannot decode name (bad label)')
    }
  }

  name.decode.bytes = consumedBytes
  return firstLabel ? '.' : result
}

name.decode.bytes = 0

name.encodingLength = function (n) {
  if (n === '.' || n === '..') return 1
  let start = 0
  let end = n.length
  if (end > 0 && n.charCodeAt(0) === 0x2E) start = 1
  if (end > start && n.charCodeAt(end - 1) === 0x2E) end--
  return byteLengthAscii(start > 0 || end < n.length ? n.substring(start, end) : n) + 2
}

const string = {}

string.encode = function (s, buf, offset) {
  if (!buf) buf = Buffer.alloc(string.encodingLength(s))
  if (!offset) offset = 0

  const len = asciiWrite(s, buf, offset + 1)
  buf[offset] = len
  string.encode.bytes = len + 1
  return buf
}

string.encode.bytes = 0

string.decode = function (buf, offset) {
  if (!offset) offset = 0

  const len = buf[offset]
  const s = asciiToString(buf, offset + 1, len)
  string.decode.bytes = len + 1
  return s
}

string.decode.bytes = 0

string.encodingLength = function (s) {
  return byteLengthAscii(s) + 1
}

const header = {}

header.encode = function (h, buf, offset) {
  if (!buf) buf = header.encodingLength(h)
  if (!offset) offset = 0

  const flags = (h.flags || 0) & 32767
  const type = h.type === 'response' ? RESPONSE_FLAG : QUERY_FLAG

  buf[offset] = (h.id || 0) >> 8; buf[offset + 1] = (h.id || 0) & 0xff
  buf[offset + 2] = (flags | type) >> 8; buf[offset + 2 + 1] = (flags | type) & 0xff
  buf[offset + 4] = (h.questions.length) >> 8; buf[offset + 4 + 1] = (h.questions.length) & 0xff
  buf[offset + 6] = (h.answers.length) >> 8; buf[offset + 6 + 1] = (h.answers.length) & 0xff
  buf[offset + 8] = (h.authorities.length) >> 8; buf[offset + 8 + 1] = (h.authorities.length) & 0xff
  buf[offset + 10] = (h.additionals.length) >> 8; buf[offset + 10 + 1] = (h.additionals.length) & 0xff

  return buf
}

header.encode.bytes = 12

header.decode = function (buf, offset) {
  if (!offset) offset = 0
  if (buf.length < 12) throw new Error('Header must be 12 bytes')
  const flags = ((buf[offset + 2] << 8) | buf[offset + 2 + 1])
  const id = ((buf[offset] << 8) | buf[offset + 1])

  // Pre-compute all flag values in one pass
  const isResponse = (flags & RESPONSE_FLAG) !== 0

  return {
    id: id,
    type: isResponse ? 'response' : 'query',
    flags: flags & 32767,
    flag_qr: isResponse,
    opcode: opcodes.toString((flags >>> 11) & 0xf),
    flag_aa: (flags & 0x400) !== 0,
    flag_tc: (flags & 0x200) !== 0,
    flag_rd: (flags & 0x100) !== 0,
    flag_ra: (flags & 0x80) !== 0,
    flag_z: (flags & 0x40) !== 0,
    flag_ad: (flags & 0x20) !== 0,
    flag_cd: (flags & 0x10) !== 0,
    rcode: rcodes.toString(flags & 0xf),
    questions: new Array(((buf[offset + 4] << 8) | buf[offset + 4 + 1])),
    answers: new Array(((buf[offset + 6] << 8) | buf[offset + 6 + 1])),
    authorities: new Array(((buf[offset + 8] << 8) | buf[offset + 8 + 1])),
    additionals: new Array(((buf[offset + 10] << 8) | buf[offset + 10 + 1]))
  }
}

header.decode.bytes = 12

header.encodingLength = function () {
  return 12
}

const runknown = exports.unknown = {}

runknown.encode = function (data, buf, offset) {
  if (!buf) buf = Buffer.alloc(runknown.encodingLength(data))
  if (!offset) offset = 0

  buf[offset] = (data.length) >> 8; buf[offset + 1] = (data.length) & 0xff
  data.copy(buf, offset + 2)

  runknown.encode.bytes = data.length + 2
  return buf
}

runknown.encode.bytes = 0

runknown.decode = function (buf, offset) {
  if (!offset) offset = 0

  const len = ((buf[offset] << 8) | buf[offset + 1])
  const data = buf.subarray(offset + 2, offset + 2 + len)
  runknown.decode.bytes = len + 2
  return data
}

runknown.decode.bytes = 0

runknown.encodingLength = function (data) {
  return data.length + 2
}

const rns = exports.ns = {}

rns.encode = function (data, buf, offset) {
  if (!buf) buf = Buffer.alloc(rns.encodingLength(data))
  if (!offset) offset = 0

  name.encode(data, buf, offset + 2)
  buf[offset] = (name.encode.bytes) >> 8; buf[offset + 1] = (name.encode.bytes) & 0xff
  rns.encode.bytes = name.encode.bytes + 2
  return buf
}

rns.encode.bytes = 0

rns.decode = function (buf, offset) {
  if (!offset) offset = 0

  const len = ((buf[offset] << 8) | buf[offset + 1])
  const dd = name.decode(buf, offset + 2)

  rns.decode.bytes = len + 2
  return dd
}

rns.decode.bytes = 0

rns.encodingLength = function (data) {
  return name.encodingLength(data) + 2
}

const rsoa = exports.soa = {}

rsoa.encode = function (data, buf, offset) {
  if (!buf) buf = Buffer.alloc(rsoa.encodingLength(data))
  if (!offset) offset = 0

  const oldOffset = offset
  offset += 2
  name.encode(data.mname, buf, offset)
  offset += name.encode.bytes
  name.encode(data.rname, buf, offset, { mail: true })
  offset += name.encode.bytes
  buf[offset] = (data.serial || 0) >>> 24; buf[offset + 1] = ((data.serial || 0) >>> 16) & 0xff; buf[offset + 2] = ((data.serial || 0) >>> 8) & 0xff; buf[offset + 3] = (data.serial || 0) & 0xff
  offset += 4
  buf[offset] = (data.refresh || 0) >>> 24; buf[offset + 1] = ((data.refresh || 0) >>> 16) & 0xff; buf[offset + 2] = ((data.refresh || 0) >>> 8) & 0xff; buf[offset + 3] = (data.refresh || 0) & 0xff
  offset += 4
  buf[offset] = (data.retry || 0) >>> 24; buf[offset + 1] = ((data.retry || 0) >>> 16) & 0xff; buf[offset + 2] = ((data.retry || 0) >>> 8) & 0xff; buf[offset + 3] = (data.retry || 0) & 0xff
  offset += 4
  buf[offset] = (data.expire || 0) >>> 24; buf[offset + 1] = ((data.expire || 0) >>> 16) & 0xff; buf[offset + 2] = ((data.expire || 0) >>> 8) & 0xff; buf[offset + 3] = (data.expire || 0) & 0xff
  offset += 4
  buf[offset] = (data.minimum || 0) >>> 24; buf[offset + 1] = ((data.minimum || 0) >>> 16) & 0xff; buf[offset + 2] = ((data.minimum || 0) >>> 8) & 0xff; buf[offset + 3] = (data.minimum || 0) & 0xff
  offset += 4

  buf[oldOffset] = (offset - oldOffset - 2) >> 8; buf[oldOffset + 1] = (offset - oldOffset - 2) & 0xff
  rsoa.encode.bytes = offset - oldOffset
  return buf
}

rsoa.encode.bytes = 0

rsoa.decode = function (buf, offset) {
  if (!offset) offset = 0

  const oldOffset = offset

  const data = Object.create(null)
  offset += 2
  data.mname = name.decode(buf, offset)
  offset += name.decode.bytes
  data.rname = name.decode(buf, offset, { mail: true })
  offset += name.decode.bytes
  data.serial = ((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3])
  offset += 4
  data.refresh = ((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3])
  offset += 4
  data.retry = ((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3])
  offset += 4
  data.expire = ((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3])
  offset += 4
  data.minimum = ((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3])
  offset += 4

  rsoa.decode.bytes = offset - oldOffset
  return data
}

rsoa.decode.bytes = 0

rsoa.encodingLength = function (data) {
  return 22 + name.encodingLength(data.mname) + name.encodingLength(data.rname)
}

const rtxt = exports.txt = {}

rtxt.encode = function (data, buf, offset) {
  if (!Array.isArray(data)) data = [data]
  for (let i = 0; i < data.length; i++) {
    if (typeof data[i] === 'string') {
      data[i] = Buffer.from(data[i])
    }
    if (!Buffer.isBuffer(data[i])) {
      throw new Error('Must be a Buffer')
    }
  }

  if (!buf) buf = Buffer.alloc(rtxt.encodingLength(data))
  if (!offset) offset = 0

  const oldOffset = offset
  offset += 2

  data.forEach(function (d) {
    buf[offset++] = d.length
    d.copy(buf, offset, 0, d.length)
    offset += d.length
  })

  buf[oldOffset] = (offset - oldOffset - 2) >> 8; buf[oldOffset + 1] = (offset - oldOffset - 2) & 0xff
  rtxt.encode.bytes = offset - oldOffset
  return buf
}

rtxt.encode.bytes = 0

rtxt.decode = function (buf, offset) {
  if (!offset) offset = 0
  const oldOffset = offset
  let remaining = ((buf[offset] << 8) | buf[offset + 1])
  offset += 2

  let data = []
  while (remaining > 0) {
    const len = buf[offset++]
    --remaining
    if (remaining < len) {
      throw new Error('Buffer overflow')
    }
    data.push(buf.subarray(offset, offset + len))
    offset += len
    remaining -= len
  }

  rtxt.decode.bytes = offset - oldOffset
  return data
}

rtxt.decode.bytes = 0

rtxt.encodingLength = function (data) {
  if (!Array.isArray(data)) data = [data]
  let length = 2
  data.forEach(function (buf) {
    if (typeof buf === 'string') {
      length += Buffer.byteLength(buf) + 1
    } else {
      length += buf.length + 1
    }
  })
  return length
}

const rnull = exports.null = {}

rnull.encode = function (data, buf, offset) {
  if (!buf) buf = Buffer.alloc(rnull.encodingLength(data))
  if (!offset) offset = 0

  if (typeof data === 'string') data = Buffer.from(data)
  if (!data) data = Buffer.alloc(0)

  const oldOffset = offset
  offset += 2

  const len = data.length
  data.copy(buf, offset, 0, len)
  offset += len

  buf[oldOffset] = (offset - oldOffset - 2) >> 8; buf[oldOffset + 1] = (offset - oldOffset - 2) & 0xff
  rnull.encode.bytes = offset - oldOffset
  return buf
}

rnull.encode.bytes = 0

rnull.decode = function (buf, offset) {
  if (!offset) offset = 0
  const oldOffset = offset
  const len = ((buf[offset] << 8) | buf[offset + 1])

  offset += 2

  const data = buf.subarray(offset, offset + len)
  offset += len

  rnull.decode.bytes = offset - oldOffset
  return data
}

rnull.decode.bytes = 0

rnull.encodingLength = function (data) {
  if (!data) return 2
  return (Buffer.isBuffer(data) ? data.length : Buffer.byteLength(data)) + 2
}

const rhinfo = exports.hinfo = {}

rhinfo.encode = function (data, buf, offset) {
  if (!buf) buf = Buffer.alloc(rhinfo.encodingLength(data))
  if (!offset) offset = 0

  const oldOffset = offset
  offset += 2
  string.encode(data.cpu, buf, offset)
  offset += string.encode.bytes
  string.encode(data.os, buf, offset)
  offset += string.encode.bytes
  buf[oldOffset] = (offset - oldOffset - 2) >> 8; buf[oldOffset + 1] = (offset - oldOffset - 2) & 0xff
  rhinfo.encode.bytes = offset - oldOffset
  return buf
}

rhinfo.encode.bytes = 0

rhinfo.decode = function (buf, offset) {
  if (!offset) offset = 0

  const oldOffset = offset

  const data = Object.create(null)
  offset += 2
  data.cpu = string.decode(buf, offset)
  offset += string.decode.bytes
  data.os = string.decode(buf, offset)
  offset += string.decode.bytes
  rhinfo.decode.bytes = offset - oldOffset
  return data
}

rhinfo.decode.bytes = 0

rhinfo.encodingLength = function (data) {
  return string.encodingLength(data.cpu) + string.encodingLength(data.os) + 2
}

const rptr = exports.ptr = {}
const rcname = exports.cname = rptr
const rdname = exports.dname = rptr

rptr.encode = function (data, buf, offset) {
  if (!buf) buf = Buffer.alloc(rptr.encodingLength(data))
  if (!offset) offset = 0

  name.encode(data, buf, offset + 2)
  buf[offset] = (name.encode.bytes) >> 8; buf[offset + 1] = (name.encode.bytes) & 0xff
  rptr.encode.bytes = name.encode.bytes + 2
  return buf
}

rptr.encode.bytes = 0

rptr.decode = function (buf, offset) {
  if (!offset) offset = 0

  const data = name.decode(buf, offset + 2)
  rptr.decode.bytes = name.decode.bytes + 2
  return data
}

rptr.decode.bytes = 0

rptr.encodingLength = function (data) {
  return name.encodingLength(data) + 2
}

const rsrv = exports.srv = {}

rsrv.encode = function (data, buf, offset) {
  if (!buf) buf = Buffer.alloc(rsrv.encodingLength(data))
  if (!offset) offset = 0

  buf[offset + 2] = (data.priority || 0) >> 8; buf[offset + 3] = (data.priority || 0) & 0xff
  buf[offset + 4] = (data.weight || 0) >> 8; buf[offset + 5] = (data.weight || 0) & 0xff
  buf[offset + 6] = (data.port || 0) >> 8; buf[offset + 7] = (data.port || 0) & 0xff
  name.encode(data.target, buf, offset + 8)

  const len = name.encode.bytes + 6
  buf[offset] = len >> 8; buf[offset + 1] = len & 0xff

  rsrv.encode.bytes = len + 2
  return buf
}

rsrv.encode.bytes = 0

rsrv.decode = function (buf, offset) {
  if (!offset) offset = 0

  const len = ((buf[offset] << 8) | buf[offset + 1])

  const data = Object.create(null)
  data.priority = ((buf[offset + 2] << 8) | buf[offset + 2 + 1])
  data.weight = ((buf[offset + 4] << 8) | buf[offset + 4 + 1])
  data.port = ((buf[offset + 6] << 8) | buf[offset + 6 + 1])
  data.target = name.decode(buf, offset + 8)

  rsrv.decode.bytes = len + 2
  return data
}

rsrv.decode.bytes = 0

rsrv.encodingLength = function (data) {
  return 8 + name.encodingLength(data.target)
}

const rcaa = exports.caa = {}

rcaa.ISSUER_CRITICAL = 1 << 7

rcaa.encode = function (data, buf, offset) {
  const len = rcaa.encodingLength(data)

  if (!buf) buf = Buffer.alloc(rcaa.encodingLength(data))
  if (!offset) offset = 0

  if (data.issuerCritical) {
    data.flags = rcaa.ISSUER_CRITICAL
  }

  buf[offset] = (len - 2) >> 8; buf[offset + 1] = (len - 2) & 0xff
  offset += 2
  buf[offset] = data.flags || 0
  offset += 1
  string.encode(data.tag, buf, offset)
  offset += string.encode.bytes
  buf.write(data.value, offset)
  offset += Buffer.byteLength(data.value)

  rcaa.encode.bytes = len
  return buf
}

rcaa.encode.bytes = 0

rcaa.decode = function (buf, offset) {
  if (!offset) offset = 0

  const len = ((buf[offset] << 8) | buf[offset + 1])
  offset += 2

  const oldOffset = offset
  const data = Object.create(null)
  data.flags = buf[offset]
  offset += 1
  data.tag = string.decode(buf, offset)
  offset += string.decode.bytes
  data.value = buf.toString('utf-8', offset, oldOffset + len)

  data.issuerCritical = !!(data.flags & rcaa.ISSUER_CRITICAL)

  rcaa.decode.bytes = len + 2

  return data
}

rcaa.decode.bytes = 0

rcaa.encodingLength = function (data) {
  return string.encodingLength(data.tag) + string.encodingLength(data.value) + 2
}

const rmx = exports.mx = {}

rmx.encode = function (data, buf, offset) {
  if (!buf) buf = Buffer.alloc(rmx.encodingLength(data))
  if (!offset) offset = 0

  const oldOffset = offset
  offset += 2
  buf[offset] = (data.preference || 0) >> 8; buf[offset + 1] = (data.preference || 0) & 0xff
  offset += 2
  name.encode(data.exchange, buf, offset)
  offset += name.encode.bytes

  buf[oldOffset] = (offset - oldOffset - 2) >> 8; buf[oldOffset + 1] = (offset - oldOffset - 2) & 0xff
  rmx.encode.bytes = offset - oldOffset
  return buf
}

rmx.encode.bytes = 0

rmx.decode = function (buf, offset) {
  if (!offset) offset = 0

  const oldOffset = offset

  const data = Object.create(null)
  offset += 2
  data.preference = ((buf[offset] << 8) | buf[offset + 1])
  offset += 2
  data.exchange = name.decode(buf, offset)
  offset += name.decode.bytes

  rmx.decode.bytes = offset - oldOffset
  return data
}

rmx.encodingLength = function (data) {
  return 4 + name.encodingLength(data.exchange)
}

const ra = exports.a = {}

ra.encode = function (host, buf, offset) {
  if (!buf) buf = Buffer.alloc(ra.encodingLength(host))
  if (!offset) offset = 0

  buf[offset] = 0; buf[offset + 1] = 4
  offset += 2
  ip.v4.encode(host, buf, offset)
  ra.encode.bytes = 6
  return buf
}

ra.encode.bytes = 0

ra.decode = function (buf, offset) {
  if (!offset) offset = 0

  offset += 2
  const host = ip.v4.decode(buf, offset)
  ra.decode.bytes = 6
  return host
}

ra.decode.bytes = 0

ra.encodingLength = function () {
  return 6
}

const raaaa = exports.aaaa = {}

raaaa.encode = function (host, buf, offset) {
  if (!buf) buf = Buffer.alloc(raaaa.encodingLength(host))
  if (!offset) offset = 0

  buf[offset] = 0; buf[offset + 1] = 16
  offset += 2
  ip.v6.encode(host, buf, offset)
  raaaa.encode.bytes = 18
  return buf
}

raaaa.encode.bytes = 0

raaaa.decode = function (buf, offset) {
  if (!offset) offset = 0

  offset += 2
  const host = ip.v6.decode(buf, offset)
  raaaa.decode.bytes = 18
  return host
}

raaaa.decode.bytes = 0

raaaa.encodingLength = function () {
  return 18
}

const roption = exports.option = {}

roption.encode = function (option, buf, offset) {
  if (!buf) buf = Buffer.alloc(roption.encodingLength(option))
  if (!offset) offset = 0
  const oldOffset = offset

  const code = optioncodes.toCode(option.code)
  buf[offset] = (code) >> 8; buf[offset + 1] = (code) & 0xff
  offset += 2
  if (option.data) {
    buf[offset] = (option.data.length) >> 8; buf[offset + 1] = (option.data.length) & 0xff
    offset += 2
    option.data.copy(buf, offset)
    offset += option.data.length
  } else {
    switch (code) {
      // case 3: NSID.  No encode makes sense.
      // case 5,6,7: Not implementable
      case 8: // ECS
        // note: do IP math before calling
        const spl = option.sourcePrefixLength || 0
        const fam = option.family || ip.familyOf(option.ip)
        const ipBuf = ip.encode(option.ip, Buffer.alloc)
        const ipLen = Math.ceil(spl / 8)
        buf[offset] = (ipLen + 4) >> 8; buf[offset + 1] = (ipLen + 4) & 0xff
        offset += 2
        buf[offset] = (fam) >> 8; buf[offset + 1] = (fam) & 0xff
        offset += 2
        buf[offset++] = spl
        buf[offset++] = option.scopePrefixLength || 0

        ipBuf.copy(buf, offset, 0, ipLen)
        offset += ipLen
        break
      // case 9: EXPIRE (experimental)
      // case 10: COOKIE.  No encode makes sense.
      case 11: // KEEP-ALIVE
        if (option.timeout) {
          buf[offset] = (2) >> 8; buf[offset + 1] = (2) & 0xff
          offset += 2
          buf[offset] = (option.timeout) >> 8; buf[offset + 1] = (option.timeout) & 0xff
          offset += 2
        } else {
          buf[offset] = (0) >> 8; buf[offset + 1] = (0) & 0xff
          offset += 2
        }
        break
      case 12: // PADDING
        const len = option.length || 0
        buf[offset] = (len) >> 8; buf[offset + 1] = (len) & 0xff
        offset += 2
        buf.fill(0, offset, offset + len)
        offset += len
        break
      // case 13:  CHAIN.  Experimental.
      case 14: // KEY-TAG
        const tagsLen = option.tags.length * 2
        buf[offset] = (tagsLen) >> 8; buf[offset + 1] = (tagsLen) & 0xff
        offset += 2
        for (const tag of option.tags) {
          buf[offset] = (tag) >> 8; buf[offset + 1] = (tag) & 0xff
          offset += 2
        }
        break
      default:
        throw new Error(`Unknown roption code: ${option.code}`)
    }
  }

  roption.encode.bytes = offset - oldOffset
  return buf
}

roption.encode.bytes = 0

roption.decode = function (buf, offset) {
  if (!offset) offset = 0
  const option = Object.create(null)
  option.code = ((buf[offset] << 8) | buf[offset + 1])
  option.type = optioncodes.toString(option.code)
  offset += 2
  const len = ((buf[offset] << 8) | buf[offset + 1])
  offset += 2
  option.data = buf.subarray(offset, offset + len)
  switch (option.code) {
    // case 3: NSID.  No decode makes sense.
    case 8: // ECS
      option.family = ((buf[offset] << 8) | buf[offset + 1])
      offset += 2
      option.sourcePrefixLength = buf[offset++]
      option.scopePrefixLength = buf[offset++]
      const padded = Buffer.alloc((option.family === 1) ? 4 : 16)
      buf.copy(padded, 0, offset, offset + len - 4)
      option.ip = ip.decode(padded)
      break
    // case 12: Padding.  No decode makes sense.
    case 11: // KEEP-ALIVE
      if (len > 0) {
        option.timeout = ((buf[offset] << 8) | buf[offset + 1])
        offset += 2
      }
      break
    case 14:
      option.tags = []
      for (let i = 0; i < len; i += 2) {
        option.tags.push(((buf[offset] << 8) | buf[offset + 1]))
        offset += 2
      }
    // don't worry about default.  caller will use data if desired
  }

  roption.decode.bytes = len + 4
  return option
}

roption.decode.bytes = 0

roption.encodingLength = function (option) {
  if (option.data) {
    return option.data.length + 4
  }
  const code = optioncodes.toCode(option.code)
  switch (code) {
    case 8: // ECS
      const spl = option.sourcePrefixLength || 0
      return Math.ceil(spl / 8) + 8
    case 11: // KEEP-ALIVE
      return (typeof option.timeout === 'number') ? 6 : 4
    case 12: // PADDING
      return option.length + 4
    case 14: // KEY-TAG
      return 4 + (option.tags.length * 2)
  }
  throw new Error(`Unknown roption code: ${option.code}`)
}

const ropt = exports.opt = {}

ropt.encode = function (options, buf, offset) {
  if (!buf) buf = Buffer.alloc(ropt.encodingLength(options))
  if (!offset) offset = 0
  const oldOffset = offset

  const rdlen = encodingLengthList(options, roption)
  buf[offset] = (rdlen) >> 8; buf[offset + 1] = (rdlen) & 0xff
  offset = encodeList(options, roption, buf, offset + 2)

  ropt.encode.bytes = offset - oldOffset
  return buf
}

ropt.encode.bytes = 0

ropt.decode = function (buf, offset) {
  if (!offset) offset = 0
  const oldOffset = offset

  const options = []
  let rdlen = ((buf[offset] << 8) | buf[offset + 1])
  offset += 2
  let o = 0
  while (rdlen > 0) {
    options[o++] = roption.decode(buf, offset)
    offset += roption.decode.bytes
    rdlen -= roption.decode.bytes
  }
  ropt.decode.bytes = offset - oldOffset
  return options
}

ropt.decode.bytes = 0

ropt.encodingLength = function (options) {
  return 2 + encodingLengthList(options || [], roption)
}

const rdnskey = exports.dnskey = {}

rdnskey.PROTOCOL_DNSSEC = 3
rdnskey.ZONE_KEY = 0x80
rdnskey.SECURE_ENTRYPOINT = 0x8000

rdnskey.encode = function (key, buf, offset) {
  if (!buf) buf = Buffer.alloc(rdnskey.encodingLength(key))
  if (!offset) offset = 0
  const oldOffset = offset

  const keydata = key.key
  if (!Buffer.isBuffer(keydata)) {
    throw new Error('Key must be a Buffer')
  }

  offset += 2 // Leave space for length
  buf[offset] = (key.flags) >> 8; buf[offset + 1] = (key.flags) & 0xff
  offset += 2
  buf[offset] = rdnskey.PROTOCOL_DNSSEC
  offset += 1
  buf[offset] = key.algorithm
  offset += 1
  keydata.copy(buf, offset, 0, keydata.length)
  offset += keydata.length

  rdnskey.encode.bytes = offset - oldOffset
  buf[oldOffset] = (rdnskey.encode.bytes - 2) >> 8; buf[oldOffset + 1] = (rdnskey.encode.bytes - 2) & 0xff
  return buf
}

rdnskey.encode.bytes = 0

rdnskey.decode = function (buf, offset) {
  if (!offset) offset = 0
  const oldOffset = offset

  var key = Object.create(null)
  var length = ((buf[offset] << 8) | buf[offset + 1])
  offset += 2
  key.flags = ((buf[offset] << 8) | buf[offset + 1])
  offset += 2
  if (buf[offset] !== rdnskey.PROTOCOL_DNSSEC) {
    throw new Error('Protocol must be 3')
  }
  offset += 1
  key.algorithm = buf[offset]
  offset += 1
  key.key = buf.subarray(offset, oldOffset + length + 2)
  offset += key.key.length
  rdnskey.decode.bytes = offset - oldOffset
  return key
}

rdnskey.decode.bytes = 0

rdnskey.encodingLength = function (key) {
  return 6 + Buffer.byteLength(key.key)
}

const rrrsig = exports.rrsig = {}

rrrsig.encode = function (sig, buf, offset) {
  if (!buf) buf = Buffer.alloc(rrrsig.encodingLength(sig))
  if (!offset) offset = 0
  const oldOffset = offset

  const signature = sig.signature
  if (!Buffer.isBuffer(signature)) {
    throw new Error('Signature must be a Buffer')
  }

  offset += 2 // Leave space for length
  buf[offset] = (types.toType(sig.typeCovered)) >> 8; buf[offset + 1] = (types.toType(sig.typeCovered)) & 0xff
  offset += 2
  buf[offset] = sig.algorithm
  offset += 1
  buf[offset] = sig.labels
  offset += 1
  buf[offset] = (sig.originalTTL) >>> 24; buf[offset + 1] = ((sig.originalTTL) >>> 16) & 0xff; buf[offset + 2] = ((sig.originalTTL) >>> 8) & 0xff; buf[offset + 3] = (sig.originalTTL) & 0xff
  offset += 4
  buf[offset] = (sig.expiration) >>> 24; buf[offset + 1] = ((sig.expiration) >>> 16) & 0xff; buf[offset + 2] = ((sig.expiration) >>> 8) & 0xff; buf[offset + 3] = (sig.expiration) & 0xff
  offset += 4
  buf[offset] = (sig.inception) >>> 24; buf[offset + 1] = ((sig.inception) >>> 16) & 0xff; buf[offset + 2] = ((sig.inception) >>> 8) & 0xff; buf[offset + 3] = (sig.inception) & 0xff
  offset += 4
  buf[offset] = (sig.keyTag) >> 8; buf[offset + 1] = (sig.keyTag) & 0xff
  offset += 2
  name.encode(sig.signersName, buf, offset)
  offset += name.encode.bytes
  signature.copy(buf, offset, 0, signature.length)
  offset += signature.length

  rrrsig.encode.bytes = offset - oldOffset
  buf[oldOffset] = (rrrsig.encode.bytes - 2) >> 8; buf[oldOffset + 1] = (rrrsig.encode.bytes - 2) & 0xff
  return buf
}

rrrsig.encode.bytes = 0

rrrsig.decode = function (buf, offset) {
  if (!offset) offset = 0
  const oldOffset = offset

  var sig = Object.create(null)
  var length = ((buf[offset] << 8) | buf[offset + 1])
  offset += 2
  sig.typeCovered = types.toString(((buf[offset] << 8) | buf[offset + 1]))
  offset += 2
  sig.algorithm = buf[offset]
  offset += 1
  sig.labels = buf[offset]
  offset += 1
  sig.originalTTL = ((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3])
  offset += 4
  sig.expiration = ((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3])
  offset += 4
  sig.inception = ((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3])
  offset += 4
  sig.keyTag = ((buf[offset] << 8) | buf[offset + 1])
  offset += 2
  sig.signersName = name.decode(buf, offset)
  offset += name.decode.bytes
  sig.signature = buf.subarray(offset, oldOffset + length + 2)
  offset += sig.signature.length
  rrrsig.decode.bytes = offset - oldOffset
  return sig
}

rrrsig.decode.bytes = 0

rrrsig.encodingLength = function (sig) {
  return 20 +
    name.encodingLength(sig.signersName) +
    Buffer.byteLength(sig.signature)
}

const rrp = exports.rp = {}

rrp.encode = function (data, buf, offset) {
  if (!buf) buf = Buffer.alloc(rrp.encodingLength(data))
  if (!offset) offset = 0
  const oldOffset = offset

  offset += 2 // Leave space for length
  name.encode(data.mbox || '.', buf, offset, { mail: true })
  offset += name.encode.bytes
  name.encode(data.txt || '.', buf, offset)
  offset += name.encode.bytes
  rrp.encode.bytes = offset - oldOffset
  buf[oldOffset] = (rrp.encode.bytes - 2) >> 8; buf[oldOffset + 1] = (rrp.encode.bytes - 2) & 0xff
  return buf
}

rrp.encode.bytes = 0

rrp.decode = function (buf, offset) {
  if (!offset) offset = 0
  const oldOffset = offset

  const data = Object.create(null)
  offset += 2
  data.mbox = name.decode(buf, offset, { mail: true }) || '.'
  offset += name.decode.bytes
  data.txt = name.decode(buf, offset) || '.'
  offset += name.decode.bytes
  rrp.decode.bytes = offset - oldOffset
  return data
}

rrp.decode.bytes = 0

rrp.encodingLength = function (data) {
  return 2 + name.encodingLength(data.mbox || '.') + name.encodingLength(data.txt || '.')
}

const typebitmap = {}

typebitmap.encode = function (typelist, buf, offset) {
  if (!buf) buf = Buffer.alloc(typebitmap.encodingLength(typelist))
  if (!offset) offset = 0
  const oldOffset = offset

  var typesByWindow = []
  for (var i = 0; i < typelist.length; i++) {
    var typeid = types.toType(typelist[i])
    if (typesByWindow[typeid >> 8] === undefined) {
      typesByWindow[typeid >> 8] = []
    }
    typesByWindow[typeid >> 8][(typeid >> 3) & 0x1F] |= 1 << (7 - (typeid & 0x7))
  }

  for (i = 0; i < typesByWindow.length; i++) {
    if (typesByWindow[i] !== undefined) {
      var windowBuf = Buffer.from(typesByWindow[i])
      buf[offset] = i
      offset += 1
      buf[offset] = windowBuf.length
      offset += 1
      windowBuf.copy(buf, offset)
      offset += windowBuf.length
    }
  }

  typebitmap.encode.bytes = offset - oldOffset
  return buf
}

typebitmap.encode.bytes = 0

typebitmap.decode = function (buf, offset, length) {
  if (!offset) offset = 0
  const oldOffset = offset

  var typelist = []
  while (offset - oldOffset < length) {
    var window = buf[offset]
    offset += 1
    var windowLength = buf[offset]
    offset += 1
    for (var i = 0; i < windowLength; i++) {
      var b = buf[offset + i]
      for (var j = 0; j < 8; j++) {
        if (b & (1 << (7 - j))) {
          var typeid = types.toString((window << 8) | (i << 3) | j)
          typelist.push(typeid)
        }
      }
    }
    offset += windowLength
  }

  typebitmap.decode.bytes = offset - oldOffset
  return typelist
}

typebitmap.decode.bytes = 0

typebitmap.encodingLength = function (typelist) {
  var extents = []
  for (var i = 0; i < typelist.length; i++) {
    var typeid = types.toType(typelist[i])
    extents[typeid >> 8] = Math.max(extents[typeid >> 8] || 0, typeid & 0xFF)
  }

  var len = 0
  for (i = 0; i < extents.length; i++) {
    if (extents[i] !== undefined) {
      len += 2 + Math.ceil((extents[i] + 1) / 8)
    }
  }

  return len
}

const rnsec = exports.nsec = {}

rnsec.encode = function (record, buf, offset) {
  if (!buf) buf = Buffer.alloc(rnsec.encodingLength(record))
  if (!offset) offset = 0
  const oldOffset = offset

  offset += 2 // Leave space for length
  name.encode(record.nextDomain, buf, offset)
  offset += name.encode.bytes
  typebitmap.encode(record.rrtypes, buf, offset)
  offset += typebitmap.encode.bytes

  rnsec.encode.bytes = offset - oldOffset
  buf[oldOffset] = (rnsec.encode.bytes - 2) >> 8; buf[oldOffset + 1] = (rnsec.encode.bytes - 2) & 0xff
  return buf
}

rnsec.encode.bytes = 0

rnsec.decode = function (buf, offset) {
  if (!offset) offset = 0
  const oldOffset = offset

  var record = Object.create(null)
  var length = ((buf[offset] << 8) | buf[offset + 1])
  offset += 2
  record.nextDomain = name.decode(buf, offset)
  offset += name.decode.bytes
  record.rrtypes = typebitmap.decode(buf, offset, length - (offset - oldOffset))
  offset += typebitmap.decode.bytes

  rnsec.decode.bytes = offset - oldOffset
  return record
}

rnsec.decode.bytes = 0

rnsec.encodingLength = function (record) {
  return 2 +
    name.encodingLength(record.nextDomain) +
    typebitmap.encodingLength(record.rrtypes)
}

const rnsec3 = exports.nsec3 = {}

rnsec3.encode = function (record, buf, offset) {
  if (!buf) buf = Buffer.alloc(rnsec3.encodingLength(record))
  if (!offset) offset = 0
  const oldOffset = offset

  const salt = record.salt
  if (!Buffer.isBuffer(salt)) {
    throw new Error('salt must be a Buffer')
  }

  const nextDomain = record.nextDomain
  if (!Buffer.isBuffer(nextDomain)) {
    throw new Error('nextDomain must be a Buffer')
  }

  offset += 2 // Leave space for length
  buf[offset] = record.algorithm
  offset += 1
  buf[offset] = record.flags
  offset += 1
  buf[offset] = (record.iterations) >> 8; buf[offset + 1] = (record.iterations) & 0xff
  offset += 2
  buf[offset] = salt.length
  offset += 1
  salt.copy(buf, offset, 0, salt.length)
  offset += salt.length
  buf[offset] = nextDomain.length
  offset += 1
  nextDomain.copy(buf, offset, 0, nextDomain.length)
  offset += nextDomain.length
  typebitmap.encode(record.rrtypes, buf, offset)
  offset += typebitmap.encode.bytes

  rnsec3.encode.bytes = offset - oldOffset
  buf[oldOffset] = (rnsec3.encode.bytes - 2) >> 8; buf[oldOffset + 1] = (rnsec3.encode.bytes - 2) & 0xff
  return buf
}

rnsec3.encode.bytes = 0

rnsec3.decode = function (buf, offset) {
  if (!offset) offset = 0
  const oldOffset = offset

  var record = Object.create(null)
  var length = ((buf[offset] << 8) | buf[offset + 1])
  offset += 2
  record.algorithm = buf[offset]
  offset += 1
  record.flags = buf[offset]
  offset += 1
  record.iterations = ((buf[offset] << 8) | buf[offset + 1])
  offset += 2
  const saltLength = buf[offset]
  offset += 1
  record.salt = buf.subarray(offset, offset + saltLength)
  offset += saltLength
  const hashLength = buf[offset]
  offset += 1
  record.nextDomain = buf.subarray(offset, offset + hashLength)
  offset += hashLength
  record.rrtypes = typebitmap.decode(buf, offset, length - (offset - oldOffset))
  offset += typebitmap.decode.bytes

  rnsec3.decode.bytes = offset - oldOffset
  return record
}

rnsec3.decode.bytes = 0

rnsec3.encodingLength = function (record) {
  return 8 +
    record.salt.length +
    record.nextDomain.length +
    typebitmap.encodingLength(record.rrtypes)
}

const rds = exports.ds = {}

rds.encode = function (digest, buf, offset) {
  if (!buf) buf = Buffer.alloc(rds.encodingLength(digest))
  if (!offset) offset = 0
  const oldOffset = offset

  const digestdata = digest.digest
  if (!Buffer.isBuffer(digestdata)) {
    throw new Error('Digest must be a Buffer')
  }

  offset += 2 // Leave space for length
  buf[offset] = (digest.keyTag) >> 8; buf[offset + 1] = (digest.keyTag) & 0xff
  offset += 2
  buf[offset] = digest.algorithm
  offset += 1
  buf[offset] = digest.digestType
  offset += 1
  digestdata.copy(buf, offset, 0, digestdata.length)
  offset += digestdata.length

  rds.encode.bytes = offset - oldOffset
  buf[oldOffset] = (rds.encode.bytes - 2) >> 8; buf[oldOffset + 1] = (rds.encode.bytes - 2) & 0xff
  return buf
}

rds.encode.bytes = 0

rds.decode = function (buf, offset) {
  if (!offset) offset = 0
  const oldOffset = offset

  var digest = Object.create(null)
  var length = ((buf[offset] << 8) | buf[offset + 1])
  offset += 2
  digest.keyTag = ((buf[offset] << 8) | buf[offset + 1])
  offset += 2
  digest.algorithm = buf[offset]
  offset += 1
  digest.digestType = buf[offset]
  offset += 1
  digest.digest = buf.subarray(offset, oldOffset + length + 2)
  offset += digest.digest.length
  rds.decode.bytes = offset - oldOffset
  return digest
}

rds.decode.bytes = 0

rds.encodingLength = function (digest) {
  return 6 + Buffer.byteLength(digest.digest)
}

const rsshfp = exports.sshfp = {}

rsshfp.getFingerprintLengthForHashType = function getFingerprintLengthForHashType (hashType) {
  switch (hashType) {
    case 1: return 20
    case 2: return 32
  }
}

rsshfp.encode = function encode (record, buf, offset) {
  if (!buf) buf = Buffer.alloc(rsshfp.encodingLength(record))
  if (!offset) offset = 0
  const oldOffset = offset

  offset += 2 // The function call starts with the offset pointer at the RDLENGTH field, not the RDATA one
  buf[offset] = record.algorithm
  offset += 1
  buf[offset] = record.hash
  offset += 1

  const fingerprintBuf = Buffer.from(record.fingerprint.toUpperCase(), 'hex')
  if (fingerprintBuf.length !== rsshfp.getFingerprintLengthForHashType(record.hash)) {
    throw new Error('Invalid fingerprint length')
  }
  fingerprintBuf.copy(buf, offset)
  offset += fingerprintBuf.byteLength

  rsshfp.encode.bytes = offset - oldOffset
  buf[oldOffset] = (rsshfp.encode.bytes - 2) >> 8; buf[oldOffset + 1] = (rsshfp.encode.bytes - 2) & 0xff

  return buf
}

rsshfp.encode.bytes = 0

rsshfp.decode = function decode (buf, offset) {
  if (!offset) offset = 0
  const oldOffset = offset

  const record = {}
  offset += 2 // Account for the RDLENGTH field
  record.algorithm = buf[offset]
  offset += 1
  record.hash = buf[offset]
  offset += 1

  const fingerprintLength = rsshfp.getFingerprintLengthForHashType(record.hash)
  record.fingerprint = buf.subarray(offset, offset + fingerprintLength).toString('hex').toUpperCase()
  offset += fingerprintLength
  rsshfp.decode.bytes = offset - oldOffset
  return record
}

rsshfp.decode.bytes = 0

rsshfp.encodingLength = function (record) {
  return 4 + Buffer.from(record.fingerprint, 'hex').byteLength
}

const rnaptr = exports.naptr = {}

rnaptr.encode = function (data, buf, offset) {
  if (!buf) buf = Buffer.alloc(rnaptr.encodingLength(data))
  if (!offset) offset = 0
  const oldOffset = offset
  offset += 2
  buf[offset] = (data.order || 0) >> 8; buf[offset + 1] = (data.order || 0) & 0xff
  offset += 2
  buf[offset] = (data.preference || 0) >> 8; buf[offset + 1] = (data.preference || 0) & 0xff
  offset += 2
  string.encode(data.flags, buf, offset)
  offset += string.encode.bytes
  string.encode(data.services, buf, offset)
  offset += string.encode.bytes
  string.encode(data.regexp, buf, offset)
  offset += string.encode.bytes
  name.encode(data.replacement, buf, offset)
  offset += name.encode.bytes
  rnaptr.encode.bytes = offset - oldOffset
  buf[oldOffset] = (rnaptr.encode.bytes - 2) >> 8; buf[oldOffset + 1] = (rnaptr.encode.bytes - 2) & 0xff
  return buf
}

rnaptr.encode.bytes = 0

rnaptr.decode = function (buf, offset) {
  if (!offset) offset = 0
  const oldOffset = offset
  const data = Object.create(null)
  offset += 2
  data.order = ((buf[offset] << 8) | buf[offset + 1])
  offset += 2
  data.preference = ((buf[offset] << 8) | buf[offset + 1])
  offset += 2
  data.flags = string.decode(buf, offset)
  offset += string.decode.bytes
  data.services = string.decode(buf, offset)
  offset += string.decode.bytes
  data.regexp = string.decode(buf, offset)
  offset += string.decode.bytes
  data.replacement = name.decode(buf, offset)
  offset += name.decode.bytes
  rnaptr.decode.bytes = offset - oldOffset
  return data
}

rnaptr.decode.bytes = 0

rnaptr.encodingLength = function (data) {
  return string.encodingLength(data.flags) +
    string.encodingLength(data.services) +
    string.encodingLength(data.regexp) +
    name.encodingLength(data.replacement) + 6
}

const rtlsa = exports.tlsa = {}

rtlsa.encode = function (cert, buf, offset) {
  if (!buf) buf = Buffer.alloc(rtlsa.encodingLength(cert))
  if (!offset) offset = 0
  const oldOffset = offset

  const certdata = cert.certificate
  if (!Buffer.isBuffer(certdata)) {
    throw new Error('Certificate must be a Buffer')
  }

  offset += 2 // Leave space for length
  buf[offset] = cert.usage
  offset += 1
  buf[offset] = cert.selector
  offset += 1
  buf[offset] = cert.matchingType
  offset += 1
  certdata.copy(buf, offset, 0, certdata.length)
  offset += certdata.length

  rtlsa.encode.bytes = offset - oldOffset
  buf[oldOffset] = (rtlsa.encode.bytes - 2) >> 8; buf[oldOffset + 1] = (rtlsa.encode.bytes - 2) & 0xff
  return buf
}

rtlsa.encode.bytes = 0

rtlsa.decode = function (buf, offset) {
  if (!offset) offset = 0
  const oldOffset = offset

  const cert = Object.create(null)
  const length = ((buf[offset] << 8) | buf[offset + 1])
  offset += 2
  cert.usage = buf[offset]
  offset += 1
  cert.selector = buf[offset]
  offset += 1
  cert.matchingType = buf[offset]
  offset += 1
  cert.certificate = buf.subarray(offset, oldOffset + length + 2)
  offset += cert.certificate.length
  rtlsa.decode.bytes = offset - oldOffset
  return cert
}

rtlsa.decode.bytes = 0

rtlsa.encodingLength = function (cert) {
  return 5 + Buffer.byteLength(cert.certificate)
}

// Pre-built lookup map for record type number -> encoder
const rencByNum = {
  1: ra,        // A
  12: rptr,     // PTR
  5: rcname,    // CNAME
  39: rdname,   // DNAME
  16: rtxt,     // TXT
  10: rnull,    // NULL
  28: raaaa,    // AAAA
  33: rsrv,     // SRV
  13: rhinfo,   // HINFO
  257: rcaa,    // CAA
  2: rns,       // NS
  6: rsoa,      // SOA
  15: rmx,      // MX
  41: ropt,     // OPT
  48: rdnskey,  // DNSKEY
  46: rrrsig,   // RRSIG
  17: rrp,      // RP
  47: rnsec,    // NSEC
  50: rnsec3,   // NSEC3
  44: rsshfp,   // SSHFP
  43: rds,      // DS
  35: rnaptr,   // NAPTR
  52: rtlsa     // TLSA
}

const renc = exports.record = function (type) {
  // Try direct lookup first (most types are already uppercase)
  const r = rencMap[type] || rencMap[type.toUpperCase()]
  return r || runknown
}

// Get encoder by type number (avoids string conversion + toUpperCase)
function rencByTypeNum(num) {
  return rencByNum[num] || runknown
}

// Pre-built lookup map for record type -> encoder
const rencMap = {
  A: ra,
  PTR: rptr,
  CNAME: rcname,
  DNAME: rdname,
  TXT: rtxt,
  NULL: rnull,
  AAAA: raaaa,
  SRV: rsrv,
  HINFO: rhinfo,
  CAA: rcaa,
  NS: rns,
  SOA: rsoa,
  MX: rmx,
  OPT: ropt,
  DNSKEY: rdnskey,
  RRSIG: rrrsig,
  RP: rrp,
  NSEC: rnsec,
  NSEC3: rnsec3,
  SSHFP: rsshfp,
  DS: rds,
  NAPTR: rnaptr,
  TLSA: rtlsa
}

const answer = exports.answer = {}

answer.encode = function (a, buf, offset) {
  if (!buf) buf = Buffer.alloc(answer.encodingLength(a))
  if (!offset) offset = 0

  const oldOffset = offset

  name.encode(a.name, buf, offset)
  offset += name.encode.bytes

  const typeNum = types.toType(a.type)
  buf[offset] = (typeNum) >> 8; buf[offset + 1] = (typeNum) & 0xff

  if (typeNum === TYPE_OPT) { // OPT
    if (a.name !== '.') {
      throw new Error('OPT name must be root.')
    }
    buf[offset + 2] = (a.udpPayloadSize || 4096) >> 8; buf[offset + 2 + 1] = (a.udpPayloadSize || 4096) & 0xff
    buf[offset + 4] = a.extendedRcode || 0
    buf[offset + 5] = a.ednsVersion || 0
    buf[offset + 6] = (a.flags || 0) >> 8; buf[offset + 6 + 1] = (a.flags || 0) & 0xff

    offset += 8
    ropt.encode(a.options || [], buf, offset)
    offset += ropt.encode.bytes
  } else {
    let klass = classes.toClass(a.class === undefined ? 'IN' : a.class)
    if (a.flush) klass |= FLUSH_MASK // the 1st bit of the class is the flush bit
    buf[offset + 2] = (klass) >> 8; buf[offset + 2 + 1] = (klass) & 0xff
    buf[offset + 4] = (a.ttl || 0) >>> 24; buf[offset + 4 + 1] = ((a.ttl || 0) >>> 16) & 0xff; buf[offset + 4 + 2] = ((a.ttl || 0) >>> 8) & 0xff; buf[offset + 4 + 3] = (a.ttl || 0) & 0xff

    offset += 8
    const enc = rencByTypeNum(typeNum)
    enc.encode(a.data, buf, offset)
    offset += enc.encode.bytes
  }

  answer.encode.bytes = offset - oldOffset
  return buf
}

answer.encode.bytes = 0

answer.decode = function (buf, offset) {
  if (!offset) offset = 0

  const a = Object.create(null)
  const oldOffset = offset

  a.name = name.decode(buf, offset)
  offset += name.decode.bytes
  const typeNum = ((buf[offset] << 8) | buf[offset + 1])
  a.type = types.toString(typeNum)
  if (typeNum === TYPE_OPT) { // OPT type number - avoid string comparison
    a.udpPayloadSize = ((buf[offset + 2] << 8) | buf[offset + 2 + 1])
    a.extendedRcode = buf[offset + 4]
    a.ednsVersion = buf[offset + 5]
    a.flags = ((buf[offset + 6] << 8) | buf[offset + 6 + 1])
    a.flag_do = (a.flags & 0x8000) !== 0
    a.options = ropt.decode(buf, offset + 8)
    offset += 8 + ropt.decode.bytes
  } else {
    const klass = ((buf[offset + 2] << 8) | buf[offset + 2 + 1])
    a.ttl = ((buf[offset + 4] << 24) | (buf[offset + 4 + 1] << 16) | (buf[offset + 4 + 2] << 8) | buf[offset + 4 + 3])

    a.class = classes.toString(klass & NOT_FLUSH_MASK)
    a.flush = (klass & FLUSH_MASK) !== 0

    const enc = rencByTypeNum(typeNum)
    a.data = enc.decode(buf, offset + 8)
    offset += 8 + enc.decode.bytes
  }

  answer.decode.bytes = offset - oldOffset
  return a
}

answer.decode.bytes = 0

answer.encodingLength = function (a) {
  const data = (a.data !== null && a.data !== undefined) ? a.data : a.options
  return name.encodingLength(a.name) + 8 + rencByTypeNum(types.toType(a.type)).encodingLength(data)
}

const question = exports.question = {}

question.encode = function (q, buf, offset) {
  if (!buf) buf = Buffer.alloc(question.encodingLength(q))
  if (!offset) offset = 0

  const oldOffset = offset

  name.encode(q.name, buf, offset)
  offset += name.encode.bytes

  const typeNum = types.toType(q.type)
  buf[offset] = typeNum >> 8; buf[offset + 1] = typeNum & 0xff
  offset += 2

  const klass = classes.toClass(q.class === undefined ? 'IN' : q.class)
  buf[offset] = klass >> 8; buf[offset + 1] = klass & 0xff
  offset += 2

  question.encode.bytes = offset - oldOffset
  return q
}

question.encode.bytes = 0

question.decode = function (buf, offset) {
  if (!offset) offset = 0

  const oldOffset = offset
  const q = {}

  q.name = name.decode(buf, offset)
  offset += name.decode.bytes

  q.type = types.toString(((buf[offset] << 8) | buf[offset + 1]))
  offset += 2

  q.class = classes.toString(((buf[offset] << 8) | buf[offset + 1]))
  offset += 2

  const qu = !!(q.class & QU_MASK)
  if (qu) q.class &= NOT_QU_MASK

  question.decode.bytes = offset - oldOffset
  return q
}

question.decode.bytes = 0

question.encodingLength = function (q) {
  return name.encodingLength(q.name) + 4
}

exports.AUTHORITATIVE_ANSWER = 1 << 10
exports.TRUNCATED_RESPONSE = 1 << 9
exports.RECURSION_DESIRED = 1 << 8
exports.RECURSION_AVAILABLE = 1 << 7
exports.AUTHENTIC_DATA = 1 << 5
exports.CHECKING_DISABLED = 1 << 4
exports.DNSSEC_OK = 1 << 15

exports.encode = function (result, buf, offset) {
  const allocing = !buf

  if (allocing) buf = Buffer.alloc(exports.encodingLength(result))
  if (!offset) offset = 0

  const oldOffset = offset

  if (!result.questions) result.questions = []
  if (!result.answers) result.answers = []
  if (!result.authorities) result.authorities = []
  if (!result.additionals) result.additionals = []

  header.encode(result, buf, offset)
  offset += header.encode.bytes

  offset = encodeList(result.questions, question, buf, offset)
  offset = encodeList(result.answers, answer, buf, offset)
  offset = encodeList(result.authorities, answer, buf, offset)
  offset = encodeList(result.additionals, answer, buf, offset)

  exports.encode.bytes = offset - oldOffset

  return buf
}

exports.encode.bytes = 0

exports.decode = function (buf, offset) {
  if (!offset) offset = 0

  const oldOffset = offset
  const result = header.decode(buf, offset)
  offset += header.decode.bytes

  offset = decodeList(result.questions, question, buf, offset)
  offset = decodeList(result.answers, answer, buf, offset)
  offset = decodeList(result.authorities, answer, buf, offset)
  offset = decodeList(result.additionals, answer, buf, offset)

  exports.decode.bytes = offset - oldOffset

  return result
}

exports.decode.bytes = 0

exports.encodingLength = function (result) {
  let len = 12

  // Inline question encodingLength (questions always use question encoder)
  const questions = result.questions || []
  for (let i = 0; i < questions.length; i++) {
    len += name.encodingLength(questions[i].name) + 4
  }

  // Answers, authorities, additionals use answer encoder
  len += encodingLengthList(result.answers || [], answer)
  len += encodingLengthList(result.authorities || [], answer)
  len += encodingLengthList(result.additionals || [], answer)

  return len
}

exports.streamEncode = function (result) {
  const len = exports.encodingLength(result)
  const buf = Buffer.alloc(len + 2)
  buf[0] = (len) >> 8; buf[0 + 1] = (len) & 0xff
  exports.encode(result, buf, 2)
  exports.streamEncode.bytes = buf.byteLength
  return buf
}

exports.streamEncode.bytes = 0

exports.streamDecode = function (sbuf) {
  const len = ((sbuf[0] << 8) | sbuf[0 + 1])
  if (sbuf.byteLength < len + 2) {
    // not enough data
    return null
  }
  const result = exports.decode(sbuf.subarray(2))
  exports.streamDecode.bytes = exports.decode.bytes
  return result
}

exports.streamDecode.bytes = 0

function encodingLengthList (list, enc) {
  let len = 0
  for (let i = 0; i < list.length; i++) len += enc.encodingLength(list[i])
  return len
}

function encodeList (list, enc, buf, offset) {
  for (let i = 0; i < list.length; i++) {
    enc.encode(list[i], buf, offset)
    offset += enc.encode.bytes
  }
  return offset
}

function decodeList (list, enc, buf, offset) {
  for (let i = 0; i < list.length; i++) {
    list[i] = enc.decode(buf, offset)
    offset += enc.decode.bytes
  }
  return offset
}
