'use strict'

const dns = require('../')
const Buffer = require('buffer').Buffer

// ─── Profiling Script ─────────────────────────────────────
// Run with: node --prof benchmarks/profile.js
// Then: node --prof-process isolate-0xNNNNNNNNNNNN-v8.log

const ITERATIONS = 500000

console.log('=== dns-packet Profiling Run ===')
console.log(`Iterations: ${ITERATIONS}`)
console.log(`PID: ${process.pid}`)
console.log()

// Test data
const simpleQuery = {
  id: 1,
  type: 'query',
  flags: dns.RECURSION_DESIRED,
  questions: [{ name: 'example.com', type: 'A', class: 'IN' }]
}

const complexResponse = {
  id: 1337,
  type: 'response',
  flags: dns.RECURSION_DESIRED | dns.RECURSION_AVAILABLE,
  questions: [{ name: 'example.com', type: 'A', class: 'IN' }],
  answers: [
    { name: 'example.com', type: 'A', class: 'IN', ttl: 300, data: '1.2.3.4' },
    { name: 'example.com', type: 'AAAA', class: 'IN', ttl: 300, data: '2001:db8::1' },
    { name: 'example.com', type: 'MX', class: 'IN', ttl: 3600, data: { preference: 10, exchange: 'mail.example.com' } },
    { name: 'example.com', type: 'NS', class: 'IN', ttl: 86400, data: 'ns1.example.com' },
    { name: 'example.com', type: 'TXT', class: 'IN', ttl: 300, data: ['v=spf1 include:_spf.example.com ~all'] }
  ],
  authorities: [{
    name: 'example.com', type: 'SOA', class: 'IN', ttl: 3600,
    data: { mname: 'ns1.example.com', rname: 'admin.example.com', serial: 2024010101, refresh: 3600, retry: 900, expire: 604800, minimum: 86400 }
  }],
  additionals: [{ name: '.', type: 'OPT', udpPayloadSize: 4096, extendedRcode: 0, ednsVersion: 0, flags: 0, options: [] }]
}

const simpleQueryBuf = dns.encode(simpleQuery)
const complexResponseBuf = dns.encode(complexResponse)

// Phase 1: Encode profiling
console.log('Running encode profiling...')
for (let i = 0; i < ITERATIONS; i++) {
  dns.encode(simpleQuery)
  dns.encode(complexResponse)
}

// Phase 2: Decode profiling
console.log('Running decode profiling...')
for (let i = 0; i < ITERATIONS; i++) {
  dns.decode(simpleQueryBuf)
  dns.decode(complexResponseBuf)
}

// Phase 3: Name encode/decode profiling (hot path)
console.log('Running name encode/decode profiling...')
for (let i = 0; i < ITERATIONS; i++) {
  const buf = Buffer.alloc(dns.name.encodingLength('www.example.com'))
  dns.name.encode('www.example.com', buf, 0)
  dns.name.decode(buf, 0)
}

// Phase 4: encodingLength profiling
console.log('Running encodingLength profiling...')
for (let i = 0; i < ITERATIONS; i++) {
  dns.encodingLength(simpleQuery)
  dns.encodingLength(complexResponse)
}

// Phase 5: streamEncode/streamDecode profiling
console.log('Running stream encode/decode profiling...')
for (let i = 0; i < ITERATIONS; i++) {
  const encoded = dns.streamEncode(simpleQuery)
  dns.streamDecode(encoded)
}

console.log()
console.log('Profiling complete. Analyze with:')
console.log('  node --prof-process isolate-*.log > benchmarks/results/profile.txt')
