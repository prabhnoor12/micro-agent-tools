/**
 * SourceMap Hero — VLQ Base64 Decoder
 * Standard Variable-Length Quantity (VLQ) decoder for SourceMap V3 mappings.
 */

const VlqDecoder = (() => {

  const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const CHAR_MAP = new Map();
  for (let i = 0; i < CHARS.length; i++) {
    CHAR_MAP.set(CHARS[i], i);
  }

  const VLQ_BASE_SHIFT = 5;
  const VLQ_BASE = 1 << VLQ_BASE_SHIFT; // 32
  const VLQ_BASE_MASK = VLQ_BASE - 1;   // 31
  const VLQ_CONTINUATION_BIT = VLQ_BASE; // 32

  /**
   * Decode a VLQ string segment into array of integer fields
   */
  function decodeString(str) {
    const values = [];
    let shift = 0;
    let value = 0;

    for (let i = 0; i < str.length; i++) {
      const c = str[i];
      const integer = CHAR_MAP.get(c);
      if (integer === undefined) continue;

      const hasContinuation = (integer & VLQ_CONTINUATION_BIT) !== 0;
      value += (integer & VLQ_BASE_MASK) << shift;

      if (hasContinuation) {
        shift += VLQ_BASE_SHIFT;
      } else {
        const isNegative = (value & 1) === 1;
        const finalValue = value >> 1;
        values.push(isNegative ? -finalValue : finalValue);
        value = 0;
        shift = 0;
      }
    }

    return values;
  }

  const vlq = {
    decodeString
  };

  if (typeof window !== 'undefined') {
    window.VlqDecoder = vlq;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = vlq;
  }

  return vlq;

})();
