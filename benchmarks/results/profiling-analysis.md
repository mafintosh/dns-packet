# dns-packet Profiling Analysis

## Test Environment
- Node.js: v24.16.0
- Platform: linux x64
- Iterations: 500,000 per phase

## Top Hotspots (by JS ticks)

| Rank | Function | Ticks | % JS | Category |
|------|----------|-------|------|----------|
| 1 | name.encode | 274 | 4.3% | Encode hot path |
| 2 | name.decode | 251 | 4.0% | Decode hot path |
| 3 | ArrayPrototypeJoin | 247 | 3.9% | Called from name.decode |
| 4 | RegExpReplace | 226 | 3.6% | Regex in name.encode/encodingLength |
| 5 | RegExp ^\.|\.$ | 210 | 3.3% | Regex compilation/matching |
| 6 | StringPrototypeReplace | 127 | 2.0% | String replace overhead |
| 7 | answer.encode | 99 | 1.6% | Answer encoding |
| 8 | answer.decode | 89 | 1.4% | Answer decoding |
| 9 | answer.encodingLength | 79 | 1.2% | Encoding length calculation |
| 10 | writeUInt16BE | 70 | 1.1% | Buffer writes |
| 11 | exports.encodingLength | 69 | 1.1% | Top-level encoding length |
| 12 | exports.decode | 54 | 0.9% | Top-level decode |
| 13 | header.decode | 43 | 0.7% | Header decoding |
| 14 | header.encode | 42 | 0.7% | Header encoding |
| 15 | StringPrototypeSplit | 29 | 0.5% | Called from name.encode |

## Identified Bottlenecks

### 1. Regex in name.encode and name.encodingLength (CRITICAL - ~9% total)
- `str.replace(/^\.|\.$/gm, '')` strips leading/trailing dots
- This regex is compiled and executed on EVERY call
- The `gm` flags are unnecessary for this use case
- Combined regex cost: 3.3% + 3.6% + 2.0% = ~9% of JS time
- **Fix**: Replace with simple string length checks

### 2. Array.join in name.decode (3.9% of JS time)
- `list.join('.')` creates a new string from array of labels
- Array allocation + join is expensive
- **Fix**: Build string manually using concatenation or pre-sized buffer

### 3. String.split in name.encode (0.5% + overhead)
- `n.split('.')` creates a new array each call
- Additional array iteration overhead
- **Fix**: Iterate over string directly, finding dot positions

### 4. Buffer allocation in streamEncode
- `Buffer.concat([sbuf, buf])` allocates 2 buffers + concatenation
- **Fix**: Pre-allocate single buffer with 2 extra bytes

### 5. Header decode object creation (0.7%)
- Creates new object with 13 properties each call
- **Fix**: Avoid redundant flag fields when not needed

### 6. Double encodingLength computation
- `exports.encode` calls `encodingLength` then encodes
- Some encodingLength functions re-compute what encode will compute
- **Fix**: Allow passing pre-computed encoding length

## Optimization Plan (Priority Order)

1. **Eliminate regex in name.encode/encodingLength** - ~9% potential gain
2. **Optimize name.decode string building** - ~4% potential gain
3. **Avoid string.split in name.encode** - ~2% potential gain
4. **Optimize streamEncode buffer allocation** - ~1-2% potential gain
5. **Cache type lookups in renc/answer.encode** - ~1-2% potential gain
6. **Reduce object allocations in header.decode** - ~1% potential gain
