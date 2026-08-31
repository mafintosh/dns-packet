# dns-packet Performance Optimization Report

## Summary

Performance optimization of the `dns-packet` library (v5.6.1) achieved measurable improvements across encode, decode, and round-trip operations. All 636 existing tests continue to pass with no behavioral changes.

## Environment

- **Node.js**: v24.16.0
- **Platform**: linux x64
- **Benchmark iterations**: 100,000 per test

## Baseline vs Optimized Results

### Encode Performance

| Benchmark | Baseline | Optimized | Improvement |
|-----------|----------|-----------|-------------|
| Simple A query | 1.10 µs/op | 0.94 µs/op | **15% faster** |
| Complex response (A+AAAA+MX+NS+TXT+SOA+OPT) | 5.12 µs/op | 3.93 µs/op | **23% faster** |
| SRV query | 1.24 µs/op | 1.04 µs/op | **16% faster** |
| SRV response | 2.70 µs/op | 2.19 µs/op | **19% faster** |
| CAA response | 1.62 µs/op | 1.37 µs/op | **15% faster** |

### Decode Performance

| Benchmark | Baseline | Optimized | Improvement |
|-----------|----------|-----------|-------------|
| Simple A query | 0.41 µs/op | 0.35 µs/op | **15% faster** |
| Complex response | 4.83 µs/op | 4.00 µs/op | **17% faster** |
| SRV query | 0.50 µs/op | 0.43 µs/op | **14% faster** |
| SRV response | 1.90 µs/op | 1.55 µs/op | **18% faster** |
| CAA response | 0.77 µs/op | 0.64 µs/op | **17% faster** |

### Round-trip Performance

| Benchmark | Baseline | Optimized | Improvement |
|-----------|----------|-----------|-------------|
| Simple A query | 1.52 µs/op | 1.29 µs/op | **15% faster** |
| Complex response | 10.55 µs/op | 8.50 µs/op | **19% faster** |

### Micro-benchmarks

| Benchmark | Baseline | Optimized | Improvement |
|-----------|----------|-----------|-------------|
| name.encode | 0.95 µs/op | 0.80 µs/op | **16% faster** |
| name.decode | 0.34 µs/op | 0.26 µs/op | **24% faster** |
| name.encodingLength | 0.04 µs/op | 0.02 µs/op | **50% faster** |

### Stress Test

| Benchmark | Baseline | Optimized | Improvement |
|-----------|----------|-----------|-------------|
| 10 unique queries | 16.99 µs/op | 14.27 µs/op | **16% faster** |
| 100 unique queries | 165.25 µs/op | 144.12 µs/op | **13% faster** |
| 1000 unique queries | 1693.95 µs/op | 1459.64 µs/op | **14% faster** |

## Optimizations Applied

### 1. Replace regex with charCode checks in name.encode/encodingLength
- **File**: `index.js`
- **Impact**: ~9% of JS time was spent on regex compilation/matching
- **Change**: Replaced `str.replace(/^\.|\.$/gm, '')` with direct `charCodeAt` checks for leading/trailing dots
- **Measurable gain**: name.encodingLength 2x faster, encode 15-23% faster

### 2. Eliminate array creation and join in name.decode
- **File**: `index.js`
- **Impact**: `ArrayPrototypeJoin` was 3.9% of JS time
- **Change**: Build result string directly with concatenation instead of pushing to array then joining
- **Measurable gain**: name.decode 24% faster, decode operations 15-18% faster

### 3. Eliminate Buffer.concat in streamEncode
- **File**: `index.js`
- **Impact**: Buffer.concat allocates 2 buffers then copies
- **Change**: Pre-allocate single buffer with 2 extra bytes for length prefix
- **Measurable gain**: Reduced allocations in stream encode path

### 4. Optimize bitwise DNS header decoding
- **File**: `index.js`
- **Impact**: header.decode was 0.7% of JS time with repeated shift+mask operations
- **Change**: Use direct bitmask checks (`flags & 0x400`) instead of shift+compare (`(flags >> 10) & 0x1 === 1`)
- **Measurable gain**: Faster header parsing in decode path

### 5. Replace switch-case with lookup maps in types.toString/toType
- **File**: `types.js`
- **Impact**: types.toString was 0.6%, types.toType was 0.6% of JS time
- **Change**: Pre-built object lookup maps instead of switch-case chains
- **Measurable gain**: Faster type resolution on every encode/decode

### 6. Replace switch-case with lookup maps in rcodes/opcodes/classes
- **Files**: `rcodes.js`, `opcodes.js`, `classes.js`
- **Impact**: Called on every header encode/decode
- **Change**: Pre-built object lookup maps instead of switch-case chains
- **Measurable gain**: Faster rcode/opcode/class resolution

### 7. Replace switch-case with lookup map in record encoder selection
- **File**: `index.js`
- **Impact**: `renc()` called on every answer encode/decode/encodingLength
- **Change**: Object property lookup instead of 23-case switch
- **Measurable gain**: Faster record type dispatch

### 8. Replace switch-case with lookup maps in optioncodes
- **File**: `optioncodes.js`
- **Impact**: Called for OPT record processing
- **Change**: Pre-built lookup maps
- **Measurable gain**: Faster option code resolution

### 9. Avoid String.split allocation in name.encode
- **File**: `index.js`
- **Impact**: StringPrototypeSplit was 0.5% of JS time, plus array allocation overhead
- **Change**: Direct label iteration using indexOf/substring instead of split
- **Measurable gain**: Reduced GC pressure, faster name encoding

### 10. Remove unnecessary buffer slice in exports.encode
- **File**: `index.js`
- **Impact**: Unnecessary slice when buffer is internally allocated
- **Change**: Removed sanity-check slice that created an unnecessary buffer view
- **Measurable gain**: One fewer allocation per encode

### 11. Numeric type check in answer.encode/decode
- **File**: `index.js`
- **Impact**: String comparison `a.type.toUpperCase() === 'OPT'` on every answer
- **Change**: Compare numeric type ID (41 for OPT) instead of string
- **Measurable gain**: Faster OPT detection in hot path

### 12. Use Buffer.subarray instead of slice in decode paths
- **File**: `index.js`
- **Impact**: `buf.slice()` creates a new Buffer; `buf.subarray()` creates a view
- **Change**: Replace all `buf.slice()` in decode paths with `buf.subarray()`
- **Measurable gain**: Reduced memory allocation and copying in decode path

### 13. Use Buffer.subarray in streamDecode
- **File**: `index.js`
- **Impact**: streamDecode was creating buffer copies via slice
- **Change**: Use subarray for zero-copy view creation
- **Measurable gain**: Faster stream decoding

## Correctness Verification

- All 636 original tests pass
- Round-trip correctness verified for all record types
- Stress test with 1000 unique queries verified correct decode results
- DNS name compression pointers work correctly with subarray

## Commit History

```
52404f2 perf: remove unnecessary buffer slice in exports.encode
03d89b0 perf: avoid string toUpperCase in answer.encode OPT check
1e19a50 perf: reduce object creation in record parsing with numeric type check
de6becc perf: replace buf.slice with buf.subarray in decode paths to avoid copies
fe0dc26 perf: use Buffer.subarray instead of slice in streamDecode
590e606 perf: avoid String.split allocation in name.encode with direct iteration
75e8682 perf: replace switch-case with lookup maps in optioncodes
fea8546 perf: replace switch-case with lookup map in record encoder selection
6a3d2f9 perf: replace switch-case with lookup maps in rcodes/opcodes/classes
883d93c perf: replace switch-case with lookup maps in types.toString/toType
a6b373e perf: optimize bitwise DNS header decoding with direct mask checks
e01d127 perf: eliminate Buffer.concat in streamEncode with single allocation
7f5a479 perf: eliminate array creation and join in name.decode
b8bc0a3 perf: replace regex with charCode checks in name.encode/encodingLength
655aba7 chore: add baseline benchmark and profiling setup
```

## Key Takeaways

1. **Regex elimination** was the single biggest win (~9% of total JS time removed)
2. **String.join avoidance** in name.decode provided the second biggest gain (~4% of JS time)
3. **Lookup maps** consistently outperform switch-case for frequent lookups in V8
4. **Buffer.subarray** over Buffer.slice eliminates unnecessary copies in decode paths
5. **Numeric comparisons** over string comparisons provide measurable gains in hot paths
6. All optimizations are pure JavaScript with no native addons needed
