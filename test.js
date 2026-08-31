'use strict'

const tape = require('tape')
const packet = require('./')
const rcodes = require('./rcodes')
const opcodes = require('./opcodes')
const optioncodes = require('./optioncodes')

const ip = require('@leichtgewicht/ip-codec')

const hexdump = require('./hexdump')

tape('unknown', function (t) {
  testEncoder(t, packet.unknown, Buffer.from('hello world'))
  t.end()
})

tape('txt', function (t) {
  testEncoder(t, packet.txt, [])
  testEncoder(t, packet.txt, ['hello world'])
  testEncoder(t, packet.txt, ['hello', 'world'])
  testEncoder(t, packet.txt, [Buffer.from([0, 1, 2, 3, 4, 5])])
  testEncoder(t, packet.txt, ['a', 'b', Buffer.from([0, 1, 2, 3, 4, 5])])
  testEncoder(t, packet.txt, ['', Buffer.allocUnsafe(0)])
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

tape('txt-invalid-data', function (t) {
  t.throws(function () { packet.txt.encode(null) }, 'null')
  t.throws(function () { packet.txt.encode(undefined) }, 'undefined')
  t.throws(function () { packet.txt.encode(10) }, 'number')
  t.end()
})

tape('null', function (t) {
  testEncoder(t, packet.null, Buffer.from([0, 1, 2, 3, 4, 5]))
  t.end()
})

tape('hinfo', function (t) {
  testEncoder(t, packet.hinfo, { cpu: 'intel', os: 'best one' })
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
  testEncoder(t, packet.srv, { port: 9999, target: 'hello.world.com' })
  testEncoder(t, packet.srv, { port: 9999, target: 'hello.world.com', priority: 42, weight: 10 })
  t.end()
})

tape('caa', function (t) {
  testEncoder(t, packet.caa, { flags: 128, tag: 'issue', value: 'letsencrypt.org', issuerCritical: true })
  testEncoder(t, packet.caa, { tag: 'issue', value: 'letsencrypt.org', issuerCritical: true })
  testEncoder(t, packet.caa, { tag: 'issue', value: 'letsencrypt.org' })
  t.end()
})

tape('mx', function (t) {
  testEncoder(t, packet.mx, { preference: 10, exchange: 'mx.hello.world.com' })
  testEncoder(t, packet.mx, { exchange: 'mx.hello.world.com' })
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

tape('sshfp', function (t) {
  testEncoder(t, packet.sshfp, {
    algorithm: 1,
    hash: 1,
    fingerprint: 'A108C9F834354D5B37AF988141C9294822F5BC00'
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
    answers: [{
      type: 'A',
      class: 'IN',
      flush: true,
      name: 'hello.a.com',
      data: '127.0.0.1'
    }]
  })

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
      data: Buffer.from([1, 2, 3, 4, 5])
    }]
  })

  testEncoder(t, packet, {
    type: 'response',
    answers: [{
      type: 'TXT',
      name: 'emptytxt.com',
      data: ''
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
  t.ok(val.flag_qr === true, 'decode flag_qr')
  t.ok(val.flag_aa === true, 'decode flag_aa')
  t.ok(val.flag_tc === false, 'decode flag_tc')
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
  offset += packet.name.encode.bytes

  data = 'a.b.c.d.example.com'
  packet.name.encode(data, buf, offset, { mail: false })
  t.ok(packet.name.encode.bytes === 21, 'name (mail) encoding length matches')
  dd = packet.name.decode(buf, offset)
  t.ok(data === dd, 'encode/decode matches')
  offset += packet.name.encode.bytes

  data = 'a.b.c.d.example.com'
  packet.name.encode(data, buf, offset, { mail: true })
  t.ok(packet.name.encode.bytes === 21, 'name (mail) encoding length matches')
  dd = packet.name.decode(buf, offset)
  t.ok(data === dd, 'encode/decode matches')
  offset += packet.name.encode.bytes

  data = 'a\\.b.c.d.example.com'
  packet.name.encode(data, buf, offset, { mail: true })
  t.ok(packet.name.encode.bytes === 21, 'name (mail) encoding length matches')
  dd = packet.name.decode(buf, offset, { mail: true })
  t.ok(data === dd, 'encode/decode matches')
  offset += packet.name.encode.bytes

  data = 'a\\.b\\.c.d.example.com'
  packet.name.encode(data, buf, offset, { mail: true })
  t.ok(packet.name.encode.bytes === 21, 'name (mail) encoding length matches')
  dd = packet.name.decode(buf, offset, { mail: true })
  t.ok(data === dd, 'encode/decode matches')
  offset += packet.name.encode.bytes

  data = 'root\\.mail'
  packet.name.encode(data, buf, offset, { mail: true })
  t.ok(packet.name.encode.bytes === 11, 'name (mail) encoding length matches')
  dd = packet.name.decode(buf, offset, { mail: true })
  t.ok(data === dd, 'encode/decode matches')
  offset += packet.name.encode.bytes

  t.end()
})

tape('name_decoding', function (t) {
  // The two most significant bits of a valid label header must be either both zero or both one
  t.throws(function () { packet.name.decode(Buffer.from([0x80])) }, /Cannot decode name \(bad label\)$/)
  t.throws(function () { packet.name.decode(Buffer.from([0xb0])) }, /Cannot decode name \(bad label\)$/)

  // Ensure there's enough buffer to read
  t.throws(function () { packet.name.decode(Buffer.from([])) }, /Cannot decode name \(buffer overflow\)$/)
  t.throws(function () { packet.name.decode(Buffer.from([0x01, 0x00])) }, /Cannot decode name \(buffer overflow\)$/)
  t.throws(function () { packet.name.decode(Buffer.from([0x01])) }, /Cannot decode name \(buffer overflow\)$/)
  t.throws(function () { packet.name.decode(Buffer.from([0xc0])) }, /Cannot decode name \(buffer overflow\)$/)

  // Allow only pointers backwards
  t.throws(function () { packet.name.decode(Buffer.from([0xc0, 0x00])) }, /Cannot decode name \(bad pointer\)$/)
  t.throws(function () { packet.name.decode(Buffer.from([0xc0, 0x01])) }, /Cannot decode name \(bad pointer\)$/)

  // A name can be only 253 characters (when connected with dots)
  const maxLength = Buffer.alloc(255)
  maxLength.fill(Buffer.from([0x01, 0x61]), 0, 254)
  t.ok(packet.name.decode(maxLength) === new Array(127).fill('a').join('.'))

  const tooLong = Buffer.alloc(256)
  tooLong.fill(Buffer.from([0x01, 0x61]))
  t.throws(function () { packet.name.decode(tooLong) }, /Cannot decode name \(name too long\)$/)

  // Ensure jumps don't reset the total length counter
  const tooLongWithJump = Buffer.alloc(403)
  tooLongWithJump.fill(Buffer.from([0x01, 0x61]), 0, 200)
  tooLongWithJump.fill(Buffer.from([0x01, 0x61]), 201, 401)
  tooLongWithJump.set([0xc0, 0x00], 401)
  t.throws(function () { packet.name.decode(tooLongWithJump, 201) }, /Cannot decode name \(name too long\)$/)

  // Ensure a jump to a null byte doesn't add extra dots
  t.ok(packet.name.decode(Buffer.from([0x00, 0x01, 0x61, 0xc0, 0x00]), 1) === 'a')

  // Ensure deeply nested pointers don't cause "Maximum call stack size exceeded" errors
  const buf = Buffer.alloc(16386)
  for (let i = 0; i < 16384; i += 2) {
    buf.writeUInt16BE(0xc000 | i, i + 2)
  }
  t.ok(packet.name.decode(buf, 16384) === '.')

  t.end()
})

tape('stream', function (t) {
  const val = {
    type: 'query',
    id: 45632,
    flags: 0x8480,
    answers: [{
      type: 'A',
      name: 'test2.example.net',
      data: '198.51.100.1'
    }]
  }
  const buf = packet.streamEncode(val)
  const val2 = packet.streamDecode(buf)

  t.same(buf.length, packet.streamEncode.bytes, 'streamEncode.bytes was set correctly')
  t.ok(compare(t, val2.type, val.type), 'streamDecoded type match')
  t.ok(compare(t, val2.id, val.id), 'streamDecoded id match')
  t.ok(parseInt(val2.flags) === parseInt(val.flags & 0x7FFF), 'streamDecoded flags match')
  const answer = val.answers[0]
  const answer2 = val2.answers[0]
  t.ok(compare(t, answer.type, answer2.type), 'streamDecoded RR type match')
  t.ok(compare(t, answer.name, answer2.name), 'streamDecoded RR name match')
  t.ok(compare(t, answer.data, answer2.data), 'streamDecoded RR rdata match')
  t.end()
})

tape('opt', function (t) {
  const val = {
    type: 'query',
    questions: [{
      type: 'A',
      name: 'hello.a.com'
    }],
    additionals: [{
      type: 'OPT',
      name: '.',
      udpPayloadSize: 1024
    }]
  }
  testEncoder(t, packet, val)
  let buf = packet.encode(val)
  let val2 = packet.decode(buf)
  const additional1 = val.additionals[0]
  let additional2 = val2.additionals[0]
  t.ok(compare(t, additional1.name, additional2.name), 'name matches')
  t.ok(compare(t, additional1.udpPayloadSize, additional2.udpPayloadSize), 'udp payload size matches')
  t.ok(compare(t, 0, additional2.flags), 'flags match')
  additional1.flags = packet.DNSSEC_OK
  additional1.extendedRcode = 0x80
  additional1.options = [ {
    code: 'CLIENT_SUBNET', // edns-client-subnet, see RFC 7871
    ip: 'fe80::',
    sourcePrefixLength: 64
  }, {
    code: 8, // still ECS
    ip: '5.6.0.0',
    sourcePrefixLength: 16,
    scopePrefixLength: 16
  }, {
    code: 'padding',
    length: 31
  }, {
    code: 'TCP_KEEPALIVE'
  }, {
    code: 'tcp_keepalive',
    timeout: 150
  }, {
    code: 'KEY_TAG',
    tags: [1, 82, 987]
  }]
  buf = packet.encode(val)
  val2 = packet.decode(buf)
  additional2 = val2.additionals[0]
  t.ok(compare(t, 1 << 15, additional2.flags), 'DO bit set in flags')
  t.ok(compare(t, true, additional2.flag_do), 'DO bit set')
  t.ok(compare(t, additional1.extendedRcode, additional2.extendedRcode), 'extended rcode matches')
  t.ok(compare(t, 8, additional2.options[0].code))
  t.ok(compare(t, 'fe80::', additional2.options[0].ip))
  t.ok(compare(t, 64, additional2.options[0].sourcePrefixLength))
  t.ok(compare(t, '5.6.0.0', additional2.options[1].ip))
  t.ok(compare(t, 16, additional2.options[1].sourcePrefixLength))
  t.ok(compare(t, 16, additional2.options[1].scopePrefixLength))
  t.ok(compare(t, additional1.options[2].length, additional2.options[2].data.length))
  t.ok(compare(t, additional1.options[3].timeout, undefined))
  t.ok(compare(t, additional1.options[4].timeout, additional2.options[4].timeout))
  t.ok(compare(t, additional1.options[5].tags, additional2.options[5].tags))
  t.end()
})

tape('dnskey', function (t) {
  testEncoder(t, packet.dnskey, {
    flags: packet.dnskey.SECURE_ENTRYPOINT | packet.dnskey.ZONE_KEY,
    algorithm: 1,
    key: Buffer.from([0, 1, 2, 3, 4, 5])
  })
  t.end()
})

tape('rrsig', function (t) {
  const testRRSIG = {
    typeCovered: 'A',
    algorithm: 1,
    labels: 2,
    originalTTL: 3600,
    expiration: 1234,
    inception: 1233,
    keyTag: 2345,
    signersName: 'foo.com',
    signature: Buffer.from([0, 1, 2, 3, 4, 5])
  }
  testEncoder(t, packet.rrsig, testRRSIG)

  // Check the signature length is correct with extra junk at the end
  const buf = Buffer.allocUnsafe(packet.rrsig.encodingLength(testRRSIG) + 4)
  packet.rrsig.encode(testRRSIG, buf)
  const val2 = packet.rrsig.decode(buf)
  t.ok(compare(t, testRRSIG, val2))

  t.end()
})

tape('rrp', function (t) {
  testEncoder(t, packet.rp, {
    mbox: 'foo.bar.com',
    txt: 'baz.bar.com'
  })
  testEncoder(t, packet.rp, {
    mbox: 'foo.bar.com'
  })
  testEncoder(t, packet.rp, {
    txt: 'baz.bar.com'
  })
  testEncoder(t, packet.rp, {})
  t.end()
})

tape('nsec', function (t) {
  testEncoder(t, packet.nsec, {
    nextDomain: 'foo.com',
    rrtypes: ['A', 'DNSKEY', 'CAA', 'DLV']
  })
  testEncoder(t, packet.nsec, {
    nextDomain: 'foo.com',
    rrtypes: ['TXT'] // 16
  })
  testEncoder(t, packet.nsec, {
    nextDomain: 'foo.com',
    rrtypes: ['TKEY'] // 249
  })
  testEncoder(t, packet.nsec, {
    nextDomain: 'foo.com',
    rrtypes: ['RRSIG', 'NSEC']
  })
  testEncoder(t, packet.nsec, {
    nextDomain: 'foo.com',
    rrtypes: ['TXT', 'RRSIG']
  })
  testEncoder(t, packet.nsec, {
    nextDomain: 'foo.com',
    rrtypes: ['TXT', 'NSEC']
  })

  // Test with the sample NSEC from https://tools.ietf.org/html/rfc4034#section-4.3
  var sampleNSEC = Buffer.from('003704686f7374076578616d706c6503636f6d00' +
      '0006400100000003041b000000000000000000000000000000000000000000000' +
      '000000020', 'hex')
  var decoded = packet.nsec.decode(sampleNSEC)
  t.ok(compare(t, decoded, {
    nextDomain: 'host.example.com',
    rrtypes: ['A', 'MX', 'RRSIG', 'NSEC', 'UNKNOWN_1234']
  }))
  var reencoded = packet.nsec.encode(decoded)
  t.same(sampleNSEC.length, reencoded.length)
  t.same(sampleNSEC, reencoded)
  t.end()
})

tape('nsec3', function (t) {
  testEncoder(t, packet.nsec3, {
    algorithm: 1,
    flags: 0,
    iterations: 257,
    salt: Buffer.from([42, 42, 42]),
    nextDomain: Buffer.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]),
    rrtypes: ['A', 'DNSKEY', 'CAA', 'DLV']
  })
  t.end()
})

tape('ds', function (t) {
  testEncoder(t, packet.ds, {
    keyTag: 1234,
    algorithm: 1,
    digestType: 1,
    digest: Buffer.from([0, 1, 2, 3, 4, 5])
  })
  t.end()
})

tape('naptr', function (t) {
  testEncoder(t, packet.naptr, {
    order: 1,
    preference: 1,
    flags: 'S',
    services: 'SIP+D2T',
    regexp: '!^.*$!sip:customer-service@xuexample.com!',
    replacement: '_sip._udp.xuexample.com'
  })
  t.end()
})

tape('tlsa', function (t) {
  testEncoder(t, packet.tlsa, {
    usage: 3,
    selector: 1,
    matchingType: 1,
    certificate: Buffer.from([0, 1, 2, 3, 4, 5])
  })
  t.end()
})

const unhexlify = (hex) => {
  return Buffer.from(hex.match(/[\da-f]{2}/gi).map(function (h) { return parseInt(h, 16) }))
}

// <HTTPS SVCB test cases>
const debugHttps = false

const testScvbDecodeEncode = (t, testname, packetbuf, expected, skipEncode = false, skipMemcmpBufs = false) => {
  const decoded = packet.svcb.decode(packetbuf, 0)
  if (debugHttps) {
    console.log(`${testname}: decode:`)
    console.log(JSON.stringify(decoded, null, 2))
  }
  t.ok(compare(t, decoded, expected), 'svcb ' + testname + ' decode')
  const encoded = packet.svcb.encode(expected)
  if (!skipEncode) {
    if (debugHttps) {
      console.log(`${testname}: encode:`)
      hexdump(encoded)
    }
    if (!skipMemcmpBufs) {
      t.ok(compare(t, packetbuf, encoded), 'svcb ' + testname + ' encode memcmp')
    }
    // now decode the encoded buffer and check for sameness
    const recoded = packet.svcb.decode(encoded, 0)
    if (debugHttps) {
      console.log(`${testname}: recode`)
      console.log(JSON.stringify(decoded, null, 2))
    }
    t.ok(compare(t, recoded, expected), 'svcb ' + testname + ' recode')
  }
}

const testHttpsDecodeEncode = (t, testname, packetbuf, expected, skipEncode = false, skipMemcmpBufs = false) => {
  const decoded = packet.httpssvc.decode(packetbuf, 0)
  if (debugHttps) {
    console.log(`${testname}: decode:`)
    console.log(JSON.stringify(decoded, null, 2))
  }
  t.ok(compare(t, decoded, expected), 'https ' + testname + ' decode')
  const encoded = packet.httpssvc.encode(expected)
  if (!skipEncode) {
    if (debugHttps) {
      console.log(`${testname}: encode:`)
      hexdump(encoded)
    }
    if (!skipMemcmpBufs) {
      t.ok(compare(t, packetbuf, encoded), 'https ' + testname + ' encode memcmp')
    }
    // now decode the encoded buffer and check for sameness
    const recoded = packet.httpssvc.decode(encoded, 0)
    if (debugHttps) {
      console.log(`${testname}: recode`)
      console.log(JSON.stringify(decoded, null, 2))
    }
    t.ok(compare(t, recoded, expected), 'https ' + testname + ' recode')
  }
  return encoded
}

const testHttpsSvcbDecodeEncode = (t, testname, packetbuf, expected, skipEncode = false, skipMemcmpBufs = false) => {
  testScvbDecodeEncode(t, testname, packetbuf, expected, skipEncode, skipMemcmpBufs)
  return testHttpsDecodeEncode(t, testname, packetbuf, expected, skipEncode, skipMemcmpBufs)
}

tape('https svcb', function (t) {
  // for the test vectors see:
  //   https://datatracker.ietf.org/doc/rfc9460/
  //   https://github.com/MikeBishop/dns-alt-svc/blob/main/draft-ietf-dnsop-svcb-https.md

  testEncoder(t, packet.svcb, {
    priority: 16,
    name: 'foo.example.org',
    values: {
      mandatory: [
        'alpn',
        'ipv4hint'
      ],
      alpn: [
        'h2',
        'h3-19'
      ],
      ipv4hint: [
        '192.0.2.1'
      ]
    }
  }
  )

  testEncoder(t, packet.httpssvc, {
    priority: 16,
    name: 'foo.example.org',
    values: {
      mandatory: [
        'alpn',
        'ipv4hint'
      ],
      alpn: [
        'h2',
        'h3-19'
      ],
      ipv4hint: [
        '192.0.2.1'
      ]
    }
  }
  )

  // https AliasMode
  testHttpsSvcbDecodeEncode(t, 'rfc9460 case1 (AliasMode)',
    unhexlify(
      '00 13' + // rdata len
      '00 00' + // priority
      '03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00' // target
    ),
    {
      priority: 0,
      name: 'foo.example.com'
    }
  )

  // https target name is "."
  testHttpsSvcbDecodeEncode(t, 'rfc9460 case2 (target name ".")',
    unhexlify(
      '00 03' + // rdata len
      '00 01' + // priority
      '00' // target (root label)
    ),
    {
      priority: 1,
      name: '.'
    }
  )

  // https port
  testHttpsSvcbDecodeEncode(t, 'rfc9460 case3 (port)',
    unhexlify(
      '00 19' + // rdata len
      '00 10' + // priority
      '03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00' + // target
      '00 03' + // key 3
      '00 02' + // length 2
      '00 35' // value - target (root label)
    ),
    {
      priority: 16,
      name: 'foo.example.com',
      values: {
        port: 53
      }
    }
  )

  // https generic key and value
  testHttpsSvcbDecodeEncode(t, 'rfc9460 case4 (generic key,val)',
    unhexlify(
      '00 1c' + // rdata len
      '00 01' + // priority
      '03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00' + // target
      '02 9b' + // key 667
      '00 05' + // length 5
      '68 65 6c 6c 6f' // value
    ),
    {
      priority: 1,
      name: 'foo.example.com',
      values: {
        key667: 'hello'
      }
    },
    true // skipEncode, we cannot encode an unknown key
  )

  // https generic key and value with decimal escape
  testHttpsSvcbDecodeEncode(t, 'rfc9460 case5 (generic key,val with escape)',
    unhexlify(
      '00 20' + // rdata len
      '00 01' + // priority
      '03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00' + // target
      '02 9b' + // key 667
      '00 09' + // length 9
      '68 65 6c 6c 6f d2 71 6f 6f' // value
    ),
    {
      priority: 1,
      name: 'foo.example.com',
      values: {
        key667: unhexlify('68 65 6c 6c 6f d2 71 6f 6f').toString('utf-8')
      }
    },
    true // skipEncode, we cannot encode an unknown key
  )

  // https two quoted ipv6 hints
  testHttpsSvcbDecodeEncode(t, 'rfc9460 case6 (ipv6hint)',
    unhexlify(
      '00 37' + // rdata len
      '00 01' + // priority
      '03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00' + // target
      '00 06' + // key 6
      '00 20' + // length 32
      '20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01' + // first address
      '20 01 0d b8 00 00 00 00 00 00 00 00 00 53 00 01' // second address
    ),
    {
      priority: 1,
      name: 'foo.example.com',
      values: {
        ipv6hint: [
          '2001:db8::1',
          '2001:db8::53:1'
        ]
      }
    }
  )

  // https ipv6 hint using embedded ipv4 syntax [2001:db8:122:344::192.0.2.33]
  testHttpsSvcbDecodeEncode(t, 'rfc9460 case7 (ipv6hint v4 syntax)',
    unhexlify(
      '00 23' + // rdata len
      '00 01' + // priority
      '07 65 78 61 6d 70 6c 65 03 63 6f 6d 00' + // target
      '00 06' + // key 6
      '00 10' + // length 16
      '20 01 0d b8 01 22 03 44 00 00 00 00 c0 00 02 21' // address
    ),
    {
      priority: 1,
      name: 'example.com',
      values: {
        ipv6hint: [ ip.v6.decode(ip.v6.encode('2001:db8:122:344::192.0.2.33')) ]
      }
    }
  )

  // case 8
  // https 16 foo.example.org. (
  //    alpn=h2,h3-19 mandatory=ipv4hint,alpn
  //    ipv4hint=192.0.2.1
  // )
  //
  // note: this may not encode to the same buffer due to internal js
  //       ordering of the `values` object storing the params
  testHttpsSvcbDecodeEncode(t, 'rfc9460 case8 (alpn,mandatory,ipv4hint)',
    unhexlify(
      '00 30' + // rdata len
      '00 10' + // priority
      '03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 6f 72 67 00' + // target
      '00 00' + // key 0
      '00 04' + // param length 4
      '00 01' + // value: key 1
      '00 04' + // value: key 4
      '00 01' + // key 1
      '00 09' + // param length 9
      '02' + // alpn length 2
      '68 32' + // alpn value
      '05' + // alpn length 5
      '68 33 2d 31 39' + // alpn value
      '00 04' + // key 4
      '00 04' + // param length 4
      'c0 00 02 01' // param value
    ),
    {
      priority: 16,
      name: 'foo.example.org',
      values: {
        mandatory: [
          'alpn',
          'ipv4hint'
        ],
        alpn: [
          'h2',
          'h3-19'
        ],
        ipv4hint: [
          '192.0.2.1'
        ]
      }
    },
    false, // skipEncode: false
    true // skipMemcmpBufs: true, do not directly memcmp the resulting bufs, see comment above
  )

  t.end()
})

tape('cloudflare real world svcb/https', (t) => {
  const httpsBuf = unhexlify(
    'ef 23 81 80 00 01 00 01 00 00 00 01 09 63 6f 6d' +
    '6d 75 6e 69 74 79 0a 63 6c 6f 75 64 66 6c 61 72' +
    '65 03 63 6f 6d 00 00 41 00 01 09 63 6f 6d 6d 75' +
    '6e 69 74 79 0a 63 6c 6f 75 64 66 6c 61 72 65 03' +
    '63 6f 6d 00 00 41 00 01 00 00 00 3c 00 3d 00 01' +
    '00 00 01 00 06 02 68 33 02 68 32 00 04 00 08 68' +
    '12 02 43 68 12 03 43 00 06 00 20 26 06 47 00 00' +
    '00 00 00 00 00 00 00 68 12 02 43 26 06 47 00 00' +
    '00 00 00 00 00 00 00 68 12 03 43 00 00 29 02 00' +
    '00 00 00 00 00 00'
  )
  const svcbBuf = unhexlify(
    'ef 23 81 80 00 01 00 01 00 00 00 01 09 63 6f 6d' +
    '6d 75 6e 69 74 79 0a 63 6c 6f 75 64 66 6c 61 72' +
    '65 03 63 6f 6d 00 00 40 00 01 09 63 6f 6d 6d 75' +
    '6e 69 74 79 0a 63 6c 6f 75 64 66 6c 61 72 65 03' +
    '63 6f 6d 00 00 40 00 01 00 00 00 3c 00 3d 00 01' +
    '00 00 01 00 06 02 68 33 02 68 32 00 04 00 08 68' +
    '12 02 43 68 12 03 43 00 06 00 20 26 06 47 00 00' +
    '00 00 00 00 00 00 00 68 12 02 43 26 06 47 00 00' +
    '00 00 00 00 00 00 00 68 12 03 43 00 00 29 02 00' +
    '00 00 00 00 00 00'
  )

  let expected = {
    id: 61219,
    type: 'response',
    flags: 384,
    flag_qr: true,
    opcode: 'QUERY',
    flag_aa: false,
    flag_tc: false,
    flag_rd: true,
    flag_ra: true,
    flag_z: false,
    flag_ad: false,
    flag_cd: false,
    rcode: 'NOERROR',
    questions: [
      {
        name: 'community.cloudflare.com',
        type: 'HTTPS',
        class: 'IN'
      }
    ],
    answers: [
      {
        name: 'community.cloudflare.com',
        type: 'HTTPS',
        ttl: 60,
        class: 'IN',
        flush: false,
        data: {
          priority: 1,
          name: '.',
          values: {
            alpn: [
              'h3',
              'h2'
            ],
            ipv4hint: [
              '104.18.2.67',
              '104.18.3.67'
            ],
            ipv6hint: [
              '2606:4700::6812:243',
              '2606:4700::6812:343'
            ]
          }
        }
      }
    ],
    authorities: [],
    additionals: [
      {
        name: '.',
        type: 'OPT',
        udpPayloadSize: 512,
        extendedRcode: 0,
        ednsVersion: 0,
        flags: 0,
        flag_do: false,
        options: []
      }
    ]
  }

  const decodedHttps = packet.decode(httpsBuf)
  t.ok(decodedHttps, 'cloudflare real world https decoded')
  if (debugHttps) {
    console.log(`cloudflare real world: decodedHttps:`)
    console.log(JSON.stringify(decodedHttps, null, 2))
  }
  t.ok(compare(t, decodedHttps, expected), 'cloudflare real world https compare')

  const decodedSvcb = packet.decode(svcbBuf)
  t.ok(decodedSvcb, 'cloudflare real world svcb decoded')
  if (debugHttps) {
    console.log(`cloudflare real world: decodedSvcb:`)
    console.log(JSON.stringify(decodedSvcb, null, 2))
  }
  expected.questions[0].type = expected.answers[0].type = 'SVCB'
  t.ok(compare(t, decodedSvcb, expected), 'cloudflare real world svcb compare')

  t.end()
})

tape('google resolver SVCB real world', function (t) {
  const svcbBuf = unhexlify(
    'd0 90 85 80 00 01' +
    '00 02 00 00 00 04 04 5f 64 6e 73 08 72 65 73 6f' +
    '6c 76 65 72 04 61 72 70 61 00 00 40 00 01 c0 0c' +
    '00 40 00 01 00 01 51 80 00 16 00 01 03 64 6e 73' +
    '06 67 6f 6f 67 6c 65 00 00 01 00 04 03 64 6f 74' +
    'c0 0c 00 40 00 01 00 01 51 80 00 2c 00 02 03 64' +
    '6e 73 06 67 6f 6f 67 6c 65 00 00 01 00 06 02 68' +
    '32 02 68 33 00 07 00 10 2f 64 6e 73 2d 71 75 65' +
    '72 79 7b 3f 64 6e 73 7d 03 64 6e 73 06 67 6f 6f' +
    '67 6c 65 00 00 01 00 01 00 01 51 80 00 04 08 08' +
    '08 08 c0 7e 00 01 00 01 00 01 51 80 00 04 08 08' +
    '04 04 c0 7e 00 1c 00 01 00 01 51 80 00 10 20 01' +
    '48 60 48 60 00 00 00 00 00 00 00 00 88 88 c0 7e' +
    '00 1c 00 01 00 01 51 80 00 10 20 01 48 60 48 60' +
    '00 00 00 00 00 00 00 00 88 44'
  )

  const expected = {
    id: 53392,
    type: 'response',
    flags: 1408,
    flag_qr: true,
    opcode: 'QUERY',
    flag_aa: true,
    flag_tc: false,
    flag_rd: true,
    flag_ra: true,
    flag_z: false,
    flag_ad: false,
    flag_cd: false,
    rcode: 'NOERROR',
    questions: [
      {
        name: '_dns.resolver.arpa',
        type: 'SVCB',
        class: 'IN'
      }
    ],
    answers: [
      {
        name: '_dns.resolver.arpa',
        type: 'SVCB',
        ttl: 86400,
        class: 'IN',
        flush: false,
        data: {
          priority: 1,
          name: 'dns.google',
          values: {
            alpn: [
              'dot'
            ]
          }
        }
      },
      {
        name: '_dns.resolver.arpa',
        type: 'SVCB',
        ttl: 86400,
        class: 'IN',
        flush: false,
        data: {
          priority: 2,
          name: 'dns.google',
          values: {
            alpn: [
              'h2',
              'h3'
            ],
            dohpath: '/dns-query{?dns}'
          }
        }
      }
    ],
    authorities: [],
    additionals: [
      {
        name: 'dns.google',
        type: 'A',
        ttl: 86400,
        class: 'IN',
        flush: false,
        data: '8.8.8.8'
      },
      {
        name: 'dns.google',
        type: 'A',
        ttl: 86400,
        class: 'IN',
        flush: false,
        data: '8.8.4.4'
      },
      {
        name: 'dns.google',
        type: 'AAAA',
        ttl: 86400,
        class: 'IN',
        flush: false,
        data: '2001:4860:4860::8888'
      },
      {
        name: 'dns.google',
        type: 'AAAA',
        ttl: 86400,
        class: 'IN',
        flush: false,
        data: '2001:4860:4860::8844'
      }
    ]
  }

  const decodedSvcb = packet.decode(svcbBuf)
  t.ok(decodedSvcb, 'google real world svcb decoded')
  if (debugHttps) {
    console.log(`google real world svcb: decodedSvcb:`)
    console.log(JSON.stringify(decodedSvcb, null, 2))
  }
  t.ok(compare(t, decodedSvcb, expected), 'google real world svcb compare')

  // now test encoding and decoding the individual answer data
  for (let answer of expected.answers) {
    const encodedData = packet.svcb.encode(answer.data)
    const decodedData = packet.svcb.decode(encodedData)
    t.ok(compare(t, answer.data, decodedData), 'google real world answer recode')
  }

  t.end()
})

// </HTTPS SVCB test cases>

tape('unpack', function (t) {
  const buf = Buffer.from([
    0x00, 0x79,
    0xde, 0xad, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x02, 0x00, 0x02, 0x02, 0x6f, 0x6a, 0x05,
    0x62, 0x61, 0x6e, 0x67, 0x6a, 0x03, 0x63, 0x6f,
    0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
    0x00, 0x04, 0x81, 0xfa, 0x0b, 0xaa, 0xc0, 0x0f,
    0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
    0x00, 0x05, 0x02, 0x63, 0x6a, 0xc0, 0x0f, 0xc0,
    0x0f, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0e,
    0x10, 0x00, 0x02, 0xc0, 0x0c, 0xc0, 0x3a, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00,
    0x04, 0x45, 0x4d, 0x9b, 0x9c, 0xc0, 0x0c, 0x00,
    0x1c, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00,
    0x10, 0x20, 0x01, 0x04, 0x18, 0x00, 0x00, 0x50,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xf9
  ])
  const val = packet.streamDecode(buf)
  const answer = val.answers[0]
  const authority = val.authorities[1]
  t.ok(val.rcode === 'NOERROR', 'decode rcode')
  t.ok(compare(t, answer.type, 'A'), 'streamDecoded RR type match')
  t.ok(compare(t, answer.name, 'oj.bangj.com'), 'streamDecoded RR name match')
  t.ok(compare(t, answer.data, '129.250.11.170'), 'streamDecoded RR rdata match')
  t.ok(compare(t, authority.type, 'NS'), 'streamDecoded RR type match')
  t.ok(compare(t, authority.name, 'bangj.com'), 'streamDecoded RR name match')
  t.ok(compare(t, authority.data, 'oj.bangj.com'), 'streamDecoded RR rdata match')
  t.end()
})

tape('optioncodes', function (t) {
  const opts = [
    [0, 'OPTION_0'],
    [1, 'LLQ'],
    [2, 'UL'],
    [3, 'NSID'],
    [4, 'OPTION_4'],
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
    [26946, 'DEVICEID'],
    [65535, 'OPTION_65535'],
    [64000, 'OPTION_64000'],
    [65002, 'OPTION_65002'],
    [-1, null]
  ]
  for (const [code, str] of opts) {
    const s = optioncodes.toString(code)
    t.ok(compare(t, s, str), `${code} => ${str}`)
    t.ok(compare(t, optioncodes.toCode(s), code), `${str} => ${code}`)
  }
  t.ok(compare(t, optioncodes.toCode('INVALIDINVALID'), -1))
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
      if (!compare(t, a[keys[i]], b[keys[i]])) {
        return false
      }
    }
  } else if (Array.isArray(b) && !Array.isArray(a)) {
    // TXT always decode as array
    return a.toString() === b[0].toString()
  } else {
    return a === b
  }
  return true
}
