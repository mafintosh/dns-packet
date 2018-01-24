'use strict'

const tape = require('tape')
const packet = require('./')
const rcodes = require('./rcodes')
const opcodes = require('./opcodes')
const Buffer = require('safe-buffer').Buffer

tape('unknown', function (t) {
  testEncoder(t, packet.unknown, Buffer.from('hello world'))
  t.end()
})

tape('txt', function (t) {
  testEncoder(t, packet.txt, ['hello world'])
  testEncoder(t, packet.txt, ['hello', 'world'])
  testEncoder(t, packet.txt, [Buffer.from([0, 1, 2, 3, 4, 5])])
  testEncoder(t, packet.txt, ['a', 'b', Buffer.from([0, 1, 2, 3, 4, 5])])
  t.end()
})

tape('txt-scalar-string', function (t) {
  const buf = packet.txt.encode('hi')
  const val = packet.txt.decode(buf)
  t.ok(val.length === 1, 'array length')
  t.ok(val[0].toString() === 'hi', 'data')
  t.end()
})

tape('txt-scalar-buffer', function (t) {
  const data = Buffer.from([0, 1, 2, 3, 4, 5])
  const buf = packet.txt.encode(data)
  const val = packet.txt.decode(buf)
  t.ok(val.length === 1, 'array length')
  t.ok(val[0].equals(data), 'data')
  t.end()
})

tape('null', function (t) {
  testEncoder(t, packet.null, [Buffer.from([0, 1, 2, 3, 4, 5])])
  t.end()
})

tape('hinfo', function (t) {
  testEncoder(t, packet.hinfo, {cpu: 'intel', os: 'best one'})
  t.end()
})

tape('ptr', function (t) {
  testEncoder(t, packet.ptr, 'hello.world.com')
  t.end()
})

tape('cname', function (t) {
  testEncoder(t, packet.cname, 'hello.cname.world.com')
  t.end()
})

tape('dname', function (t) {
  testEncoder(t, packet.dname, 'hello.dname.world.com')
  t.end()
})

tape('srv', function (t) {
  testEncoder(t, packet.srv, {port: 9999, target: 'hello.world.com'})
  testEncoder(t, packet.srv, {port: 9999, target: 'hello.world.com', priority: 42, weight: 10})
  t.end()
})

tape('caa', function (t) {
  testEncoder(t, packet.caa, {flags: 128, tag: 'issue', value: 'letsencrypt.org', issuerCritical: true})
  testEncoder(t, packet.caa, {tag: 'issue', value: 'letsencrypt.org', issuerCritical: true})
  testEncoder(t, packet.caa, {tag: 'issue', value: 'letsencrypt.org'})
  t.end()
})

tape('ns', function (t) {
  testEncoder(t, packet.ns, 'ns.world.com')
  t.end()
})

tape('soa', function (t) {
  testEncoder(t, packet.soa, {
    mname: 'hello.world.com',
    rname: 'root.hello.world.com',
    serial: 2018010400,
    refresh: 14400,
    retry: 3600,
    expire: 604800,
    minimum: 3600
  })
  t.end()
})

tape('a', function (t) {
  testEncoder(t, packet.a, '127.0.0.1')
  t.end()
})

tape('aaaa', function (t) {
  testEncoder(t, packet.aaaa, 'fe80::1')
  t.end()
})

tape('query', function (t) {
  testEncoder(t, packet, {
    type: 'query',
    questions: [{
      type: 'A',
      name: 'hello.a.com'
    }, {
      type: 'SRV',
      name: 'hello.srv.com'
    }]
  })

  testEncoder(t, packet, {
    type: 'query',
    id: 42,
    questions: [{
      type: 'A',
      class: 'IN',
      name: 'hello.a.com'
    }, {
      type: 'SRV',
      name: 'hello.srv.com'
    }]
  })

  testEncoder(t, packet, {
    type: 'query',
    id: 42,
    questions: [{
      type: 'A',
      class: 'CH',
      name: 'hello.a.com'
    }, {
      type: 'SRV',
      name: 'hello.srv.com'
    }]
  })

  t.end()
})

tape('response', function (t) {
  testEncoder(t, packet, {
    type: 'response',
    flags: packet.TRUNCATED_RESPONSE,
    answers: [{
      type: 'A',
      class: 'IN',
      name: 'hello.a.com',
      data: '127.0.0.1'
    }, {
      type: 'SRV',
      class: 'IN',
      name: 'hello.srv.com',
      data: {
        port: 9090,
        target: 'hello.target.com'
      }
    }, {
      type: 'CNAME',
      class: 'IN',
      name: 'hello.cname.com',
      data: 'hello.other.domain.com'
    }]
  })

  testEncoder(t, packet, {
    type: 'response',
    id: 100,
    flags: 0,
    additionals: [{
      type: 'AAAA',
      name: 'hello.a.com',
      data: 'fe80::1'
    }, {
      type: 'PTR',
      name: 'hello.ptr.com',
      data: 'hello.other.ptr.com'
    }, {
      type: 'SRV',
      name: 'hello.srv.com',
      ttl: 42,
      data: {
        port: 9090,
        target: 'hello.target.com'
      }
    }],
    answers: [{
      type: 'NULL',
      name: 'hello.null.com',
      data: [Buffer.from([1, 2, 3, 4, 5])]
    }]
  })

  t.end()
})

tape('rcode', function (t) {
  const errors = ['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED', 'YXDOMAIN', 'YXRRSET', 'NXRRSET', 'NOTAUTH', 'NOTZONE', 'RCODE_11', 'RCODE_12', 'RCODE_13', 'RCODE_14', 'RCODE_15']
  for (const i in errors) {
    const code = rcodes.toRcode(errors[i])
    t.ok(errors[i] === rcodes.toString(code), 'rcode conversion from/to string matches: ' + rcodes.toString(code))
  }

  const ops = ['QUERY', 'IQUERY', 'STATUS', 'OPCODE_3', 'NOTIFY', 'UPDATE', 'OPCODE_6', 'OPCODE_7', 'OPCODE_8', 'OPCODE_9', 'OPCODE_10', 'OPCODE_11', 'OPCODE_12', 'OPCODE_13', 'OPCODE_14', 'OPCODE_15']
  for (const j in ops) {
    const ocode = opcodes.toOpcode(ops[j])
    t.ok(ops[j] === opcodes.toString(ocode), 'opcode conversion from/to string matches: ' + opcodes.toString(ocode))
  }

  const buf = packet.encode({
    type: 'response',
    id: 45632,
    flags: 0x8480,
    answers: [{
      type: 'A',
      name: 'hello.example.net',
      data: '127.0.0.1'
    }]
  })
  const val = packet.decode(buf)
  t.ok(val.type === 'response', 'decode type')
  t.ok(val.opcode === 'QUERY', 'decode opcode')
  t.ok(val.flag_qr === true, 'decode flag_auth')
  t.ok(val.flag_auth === true, 'decode flag_auth')
  t.ok(val.flag_trunc === false, 'decode flag_trunc')
  t.ok(val.flag_rd === false, 'decode flag_rd')
  t.ok(val.flag_ra === true, 'decode flag_ra')
  t.ok(val.flag_z === false, 'decode flag_z')
  t.ok(val.flag_ad === false, 'decode flag_ad')
  t.ok(val.flag_cd === false, 'decode flag_cd')
  t.ok(val.rcode === 'NOERROR', 'decode rcode')
  t.end()
})

tape('name_encoding', function (t) {
  let data = 'foo.example.com'
  const buf = Buffer.allocUnsafe(255)
  let offset = 0
  packet.name.encode(data, buf, offset)
  t.ok(packet.name.encode.bytes === 17, 'name encoding length matches')
  let dd = packet.name.decode(buf, offset)
  t.ok(data === dd, 'encode/decode matches')
  offset += packet.name.encode.bytes

  data = 'com'
  packet.name.encode(data, buf, offset)
  t.ok(packet.name.encode.bytes === 5, 'name encoding length matches')
  dd = packet.name.decode(buf, offset)
  t.ok(data === dd, 'encode/decode matches')
  offset += packet.name.encode.bytes

  data = 'example.com.'
  packet.name.encode(data, buf, offset)
  t.ok(packet.name.encode.bytes === 13, 'name encoding length matches')
  dd = packet.name.decode(buf, offset)
  t.ok(data.slice(0, -1) === dd, 'encode/decode matches')
  offset += packet.name.encode.bytes

  data = '.'
  packet.name.encode(data, buf, offset)
  t.ok(packet.name.encode.bytes === 1, 'name encoding length matches')
  dd = packet.name.decode(buf, offset)
  t.ok(data === dd, 'encode/decode matches')
  t.end()
})

function testEncoder (t, rpacket, val) {
  const buf = rpacket.encode(val)
  const val2 = rpacket.decode(buf)

  t.same(buf.length, rpacket.encode.bytes, 'encode.bytes was set correctly')
  t.same(buf.length, rpacket.encodingLength(val), 'encoding length matches')
  t.ok(compare(t, val, val2), 'decoded object match')

  const buf2 = rpacket.encode(val2)
  const val3 = rpacket.decode(buf2)

  t.same(buf2.length, rpacket.encode.bytes, 'encode.bytes was set correctly on re-encode')
  t.same(buf2.length, rpacket.encodingLength(val), 'encoding length matches on re-encode')

  t.ok(compare(t, val, val3), 'decoded object match on re-encode')
  t.ok(compare(t, val2, val3), 're-encoded decoded object match on re-encode')

  const bigger = Buffer.allocUnsafe(buf2.length + 10)

  const buf3 = rpacket.encode(val, bigger, 10)
  const val4 = rpacket.decode(buf3, 10)

  t.ok(buf3 === bigger, 'echoes buffer on external buffer')
  t.same(rpacket.encode.bytes, buf.length, 'encode.bytes is the same on external buffer')
  t.ok(compare(t, val, val4), 'decoded object match on external buffer')
}

function compare (t, a, b) {
  if (Buffer.isBuffer(a)) return a.toString('hex') === b.toString('hex')
  if (typeof a === 'object' && a && b) {
    const keys = Object.keys(a)
    for (let i = 0; i < keys.length; i++) {
      if (!compare(t, a[keys[i]], b[keys[i]])) return false
    }
  } else {
    return a === b
  }
  return true
}
