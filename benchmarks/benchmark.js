'use strict'

const dns = require('../')
const Buffer = require('buffer').Buffer

// ─── Helpers ──────────────────────────────────────────────

function bench (name, fn, iterations) {
  if (!iterations) iterations = 100000

  // Warmup
  for (let i = 0; i < Math.min(1000, iterations); i++) fn()

  const start = process.hrtime.bigint()
  for (let i = 0; i < iterations; i++) fn()
  const end = process.hrtime.bigint()

  const ns = Number(end - start)
  const us = ns / 1000
  const ms = us / 1000
  const opsPerSec = iterations / (ms / 1000)

  return {
    name,
    iterations,
    totalMs: Math.round(ms * 100) / 100,
    avgUs: Math.round((us / iterations) * 100) / 100,
    opsPerSec: Math.round(opsPerSec)
  }
}

// ─── Test Data ────────────────────────────────────────────

const simpleQuery = {
  id: 1,
  type: 'query',
  flags: dns.RECURSION_DESIRED,
  questions: [{
    name: 'example.com',
    type: 'A',
    class: 'IN'
  }]
}

const complexResponse = {
  id: 1337,
  type: 'response',
  flags: dns.RECURSION_DESIRED | dns.RECURSION_AVAILABLE,
  questions: [{
    name: 'example.com',
    type: 'A',
    class: 'IN'
  }],
  answers: [{
    name: 'example.com',
    type: 'A',
    class: 'IN',
    ttl: 300,
    data: '1.2.3.4'
  }, {
    name: 'example.com',
    type: 'A',
    class: 'IN',
    ttl: 300,
    data: '5.6.7.8'
  }, {
    name: 'example.com',
    type: 'AAAA',
    class: 'IN',
    ttl: 300,
    data: '2001:db8::1'
  }, {
    name: 'example.com',
    type: 'MX',
    class: 'IN',
    ttl: 3600,
    data: { preference: 10, exchange: 'mail.example.com' }
  }, {
    name: 'example.com',
    type: 'NS',
    class: 'IN',
    ttl: 86400,
    data: 'ns1.example.com'
  }, {
    name: 'example.com',
    type: 'TXT',
    class: 'IN',
    ttl: 300,
    data: ['v=spf1 include:_spf.example.com ~all']
  }],
  authorities: [{
    name: 'example.com',
    type: 'SOA',
    class: 'IN',
    ttl: 3600,
    data: {
      mname: 'ns1.example.com',
      rname: 'admin.example.com',
      serial: 2024010101,
      refresh: 3600,
      retry: 900,
      expire: 604800,
      minimum: 86400
    }
  }],
  additionals: [{
    name: '.',
    type: 'OPT',
    udpPayloadSize: 4096,
    extendedRcode: 0,
    ednsVersion: 0,
    flags: 0,
    options: []
  }]
}

const srvQuery = {
  id: 42,
  type: 'query',
  flags: dns.RECURSION_DESIRED,
  questions: [{
    name: '_http._tcp.example.com',
    type: 'SRV',
    class: 'IN'
  }]
}

const srvResponse = {
  id: 42,
  type: 'response',
  flags: dns.RECURSION_DESIRED | dns.RECURSION_AVAILABLE,
  questions: [{
    name: '_http._tcp.example.com',
    type: 'SRV',
    class: 'IN'
  }],
  answers: [{
    name: '_http._tcp.example.com',
    type: 'SRV',
    class: 'IN',
    ttl: 300,
    data: { priority: 10, weight: 60, port: 8080, target: 'server1.example.com' }
  }, {
    name: '_http._tcp.example.com',
    type: 'SRV',
    class: 'IN',
    ttl: 300,
    data: { priority: 20, weight: 40, port: 8080, target: 'server2.example.com' }
  }]
}

const caaResponse = {
  id: 99,
  type: 'response',
  flags: dns.RECURSION_DESIRED | dns.RECURSION_AVAILABLE,
  questions: [{ name: 'example.com', type: 'CAA', class: 'IN' }],
  answers: [{
    name: 'example.com',
    type: 'CAA',
    class: 'IN',
    ttl: 300,
    data: { flags: 0, tag: 'issue', value: 'letsencrypt.org', issuerCritical: false }
  }]
}

// ─── Pre-encoded buffers for decode benchmarks ────────────

const simpleQueryBuf = dns.encode(simpleQuery)
const complexResponseBuf = dns.encode(complexResponse)
const srvQueryBuf = dns.encode(srvQuery)
const srvResponseBuf = dns.encode(srvResponse)
const caaResponseBuf = dns.encode(caaResponse)

// ─── Benchmark Suite ──────────────────────────────────────

const ITERATIONS = 100000
const results = {}

console.log('=== dns-packet Benchmark Suite ===')
console.log(`Iterations: ${ITERATIONS}`)
console.log(`Node.js: ${process.version}`)
console.log(`Date: ${new Date().toISOString()}`)
console.log()

// Encode benchmarks
console.log('--- Encode Benchmarks ---')
results.encodeSimpleQuery = bench('encode: simple A query', () => {
  dns.encode(simpleQuery)
}, ITERATIONS)
console.log(`  ${results.encodeSimpleQuery.name}: ${results.encodeSimpleQuery.avgUs} µs/op (${results.encodeSimpleQuery.opsPerSec} ops/s)`)

results.encodeComplexResponse = bench('encode: complex response (A+AAAA+MX+NS+TXT+SOA+OPT)', () => {
  dns.encode(complexResponse)
}, ITERATIONS)
console.log(`  ${results.encodeComplexResponse.name}: ${results.encodeComplexResponse.avgUs} µs/op (${results.encodeComplexResponse.opsPerSec} ops/s)`)

results.encodeSrvQuery = bench('encode: SRV query', () => {
  dns.encode(srvQuery)
}, ITERATIONS)
console.log(`  ${results.encodeSrvQuery.name}: ${results.encodeSrvQuery.avgUs} µs/op (${results.encodeSrvQuery.opsPerSec} ops/s)`)

results.encodeSrvResponse = bench('encode: SRV response', () => {
  dns.encode(srvResponse)
}, ITERATIONS)
console.log(`  ${results.encodeSrvResponse.name}: ${results.encodeSrvResponse.avgUs} µs/op (${results.encodeSrvResponse.opsPerSec} ops/s)`)

results.encodeCaaResponse = bench('encode: CAA response', () => {
  dns.encode(caaResponse)
}, ITERATIONS)
console.log(`  ${results.encodeCaaResponse.name}: ${results.encodeCaaResponse.avgUs} µs/op (${results.encodeCaaResponse.opsPerSec} ops/s)`)

// Decode benchmarks
console.log()
console.log('--- Decode Benchmarks ---')
results.decodeSimpleQuery = bench('decode: simple A query', () => {
  dns.decode(simpleQueryBuf)
}, ITERATIONS)
console.log(`  ${results.decodeSimpleQuery.name}: ${results.decodeSimpleQuery.avgUs} µs/op (${results.decodeSimpleQuery.opsPerSec} ops/s)`)

results.decodeComplexResponse = bench('decode: complex response (A+AAAA+MX+NS+TXT+SOA+OPT)', () => {
  dns.decode(complexResponseBuf)
}, ITERATIONS)
console.log(`  ${results.decodeComplexResponse.name}: ${results.decodeComplexResponse.avgUs} µs/op (${results.decodeComplexResponse.opsPerSec} ops/s)`)

results.decodeSrvQuery = bench('decode: SRV query', () => {
  dns.decode(srvQueryBuf)
}, ITERATIONS)
console.log(`  ${results.decodeSrvQuery.name}: ${results.decodeSrvQuery.avgUs} µs/op (${results.decodeSrvQuery.opsPerSec} ops/s)`)

results.decodeSrvResponse = bench('decode: SRV response', () => {
  dns.decode(srvResponseBuf)
}, ITERATIONS)
console.log(`  ${results.decodeSrvResponse.name}: ${results.decodeSrvResponse.avgUs} µs/op (${results.decodeSrvResponse.opsPerSec} ops/s)`)

results.decodeCaaResponse = bench('decode: CAA response', () => {
  dns.decode(caaResponseBuf)
}, ITERATIONS)
console.log(`  ${results.decodeCaaResponse.name}: ${results.decodeCaaResponse.avgUs} µs/op (${results.decodeCaaResponse.opsPerSec} ops/s)`)

// Round-trip correctness benchmarks
console.log()
console.log('--- Round-trip Benchmarks ---')
results.roundtripSimpleQuery = bench('roundtrip: simple A query', () => {
  const encoded = dns.encode(simpleQuery)
  dns.decode(encoded)
}, ITERATIONS)
console.log(`  ${results.roundtripSimpleQuery.name}: ${results.roundtripSimpleQuery.avgUs} µs/op (${results.roundtripSimpleQuery.opsPerSec} ops/s)`)

results.roundtripComplexResponse = bench('roundtrip: complex response', () => {
  const encoded = dns.encode(complexResponse)
  dns.decode(encoded)
}, ITERATIONS)
console.log(`  ${results.roundtripComplexResponse.name}: ${results.roundtripComplexResponse.avgUs} µs/op (${results.roundtripComplexResponse.opsPerSec} ops/s)`)

// Name encoding/decoding micro-benchmarks
console.log()
console.log('--- Name Micro-benchmarks ---')
results.nameEncode = bench('name.encode: example.com', () => {
  const buf = Buffer.alloc(dns.name.encodingLength('example.com'))
  dns.name.encode('example.com', buf, 0)
}, ITERATIONS)
console.log(`  ${results.nameEncode.name}: ${results.nameEncode.avgUs} µs/op (${results.nameEncode.opsPerSec} ops/s)`)

const nameBuf = Buffer.alloc(32)
dns.name.encode('www.subdomain.example.com', nameBuf, 0)
results.nameDecode = bench('name.decode: www.subdomain.example.com', () => {
  dns.name.decode(nameBuf, 0)
}, ITERATIONS)
console.log(`  ${results.nameDecode.name}: ${results.nameDecode.avgUs} µs/op (${results.nameDecode.opsPerSec} ops/s)`)

results.nameEncodingLength = bench('name.encodingLength: example.com', () => {
  dns.name.encodingLength('example.com')
}, ITERATIONS * 10)
console.log(`  ${results.nameEncodingLength.name}: ${results.nameEncodingLength.avgUs} µs/op (${results.nameEncodingLength.opsPerSec} ops/s)`)

// Stress test: batch encoding
console.log()
console.log('--- Stress Test: Large Packet Batches ---')
const batchSizes = [10, 100, 1000]
results.stressBatch = {}
for (const batchSize of batchSizes) {
  const packets = []
  for (let i = 0; i < batchSize; i++) {
    packets.push({
      id: i,
      type: 'query',
      flags: dns.RECURSION_DESIRED,
      questions: [{
        name: `domain${i}.example.com`,
        type: 'A',
        class: 'IN'
      }]
    })
  }

  const iters = Math.max(100, Math.floor(ITERATIONS / batchSize))
  results.stressBatch[batchSize] = bench(`stress: encode+decode ${batchSize} unique queries`, () => {
    for (let i = 0; i < batchSize; i++) {
      const encoded = dns.encode(packets[i])
      dns.decode(encoded)
    }
  }, iters)
  console.log(`  ${results.stressBatch[batchSize].name}: ${results.stressBatch[batchSize].avgUs} µs/op (${results.stressBatch[batchSize].opsPerSec} ops/s)`)

  // Verify correctness
  for (let i = 0; i < batchSize; i++) {
    const encoded = dns.encode(packets[i])
    const decoded = dns.decode(encoded)
    if (decoded.questions[0].name !== `domain${i}.example.com`) {
      console.error(`  CORRECTNESS FAILURE at batch index ${i}!`)
      process.exit(1)
    }
  }
}

// ─── Output JSON Results ──────────────────────────────────

const fs = require('fs')
const path = require('path')

const output = {
  timestamp: new Date().toISOString(),
  nodeVersion: process.version,
  platform: process.platform,
  arch: process.arch,
  iterations: ITERATIONS,
  results: {}
}

for (const [key, val] of Object.entries(results)) {
  if (val.name) {
    output.results[key] = val
  } else if (typeof val === 'object') {
    output.results[key] = {}
    for (const [k, v] of Object.entries(val)) {
      output.results[key][k] = v
    }
  }
}

const outPath = path.join(__dirname, 'results', `baseline-${Date.now()}.json`)
fs.writeFileSync(outPath, JSON.stringify(output, null, 2))
console.log()
console.log(`Results saved to: ${outPath}`)
