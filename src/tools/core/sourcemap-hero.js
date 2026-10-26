/**
 * SourceMap Hero — High Performance V3 SourceMap Parser & Stack Trace Demapper
 */

const SourceMapParser = (() => {

  class SourceMapConsumer {
    constructor(rawMapJson) {
      this.raw = typeof rawMapJson === 'string' ? JSON.parse(rawMapJson) : rawMapJson;
      this.sources = this.raw.sources || [];
      this.sourcesContent = this.raw.sourcesContent || [];
      this.names = this.raw.names || [];
      this.mappingsByLine = [];

      this._parseMappings(this.raw.mappings || "");
    }

    _parseMappings(mappingsStr) {
      const vlqDecoder = typeof VlqDecoder !== 'undefined' ? VlqDecoder : (typeof globalThis.VlqDecoder !== 'undefined' ? globalThis.VlqDecoder : (typeof require !== 'undefined' ? require('./vlq.js') : null));
      const lines = mappingsStr.split(';');
      let sourceIndex = 0;
      let originalLine = 0;
      let originalColumn = 0;
      let nameIndex = 0;

      for (let genLine = 0; genLine < lines.length; genLine++) {
        const lineStr = lines[genLine];
        const segments = lineStr.split(',');
        const lineMappings = [];
        let generatedColumn = 0;

        for (let s = 0; s < segments.length; s++) {
          const seg = segments[s];
          if (!seg) continue;

          const decoded = vlqDecoder.decodeString(seg);
          if (decoded.length === 0) continue;

          generatedColumn += decoded[0];

          let segData = {
            genCol: generatedColumn,
            sourceIndex: null,
            origLine: null,
            origCol: null,
            nameIndex: null
          };

          if (decoded.length >= 4) {
            sourceIndex += decoded[1];
            originalLine += decoded[2];
            originalColumn += decoded[3];

            segData.sourceIndex = sourceIndex;
            segData.origLine = originalLine;
            segData.origCol = originalColumn;
          }

          if (decoded.length >= 5) {
            nameIndex += decoded[4];
            segData.nameIndex = nameIndex;
          }

          lineMappings.push(segData);
        }

        // Sort segments by generated column
        lineMappings.sort((a, b) => a.genCol - b.genCol);
        this.mappingsByLine.push(lineMappings);
      }
    }

    /**
     * Look up original source position for a generated (line, col)
     * line is 1-based, col is 0 or 1-based
     */
    lookup(generatedLine, generatedCol) {
      const lineIdx = generatedLine - 1;
      if (lineIdx < 0 || lineIdx >= this.mappingsByLine.length) {
        return null;
      }

      const lineSegments = this.mappingsByLine[lineIdx];
      if (!lineSegments || lineSegments.length === 0) {
        return null;
      }

      // Find closest segment with genCol <= generatedCol
      let targetSeg = null;
      for (let i = 0; i < lineSegments.length; i++) {
        if (lineSegments[i].genCol <= generatedCol) {
          targetSeg = lineSegments[i];
        } else {
          break;
        }
      }

      if (!targetSeg && lineSegments.length > 0) {
        targetSeg = lineSegments[0];
      }

      if (!targetSeg || targetSeg.sourceIndex === null) {
        return null;
      }

      const sourceFile = this.sources[targetSeg.sourceIndex] || 'unknown';
      const origLine = targetSeg.origLine + 1; // Convert 0-based to 1-based
      const origCol = targetSeg.origCol;
      const originalName = targetSeg.nameIndex !== null ? this.names[targetSeg.nameIndex] : null;
      const content = this.sourcesContent[targetSeg.sourceIndex] || null;

      // Extract 10 lines of context around original line
      let surroundingContext = [];
      if (content) {
        const allLines = content.split(/\r?\n/);
        const startLine = Math.max(0, origLine - 6);
        const endLine = Math.min(allLines.length, origLine + 5);

        for (let idx = startLine; idx < endLine; idx++) {
          surroundingContext.push({
            lineNumber: idx + 1,
            code: allLines[idx],
            isErrorLine: (idx + 1) === origLine
          });
        }
      }

      return {
        sourceFile,
        originalLine: origLine,
        originalColumn: origCol,
        originalName,
        sourceContent: content,
        surroundingContext
      };
    }
  }

  /**
   * Demap an entire stack trace string using the provided SourceMapConsumer
   */
  function demapStackTrace(stackTraceStr, consumer) {
    if (!stackTraceStr || !consumer) return [];

    const lines = stackTraceStr.split(/\r?\n/);
    const parsedFrames = [];

    // Match stack frames like: at fnName (bundle.min.js:1:4821) or at bundle.min.js:1:4821
    const frameRegex = /at\s+(?:([^\s(]+)\s+\()?(?:.*?[/\\])?([^:)]+):(\d+):(\d+)\)?/;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      const match = line.match(frameRegex);

      if (match) {
        const functionName = match[1] || '<anonymous>';
        const filename = match[2];
        const genLine = parseInt(match[3], 10);
        const genCol = parseInt(match[4], 10);

        const mapped = consumer.lookup(genLine, genCol);

        parsedFrames.push({
          rawLine: line,
          functionName,
          filename,
          genLine,
          genCol,
          isMapped: !!mapped,
          mapped: mapped || null
        });
      } else if (line.startsWith('Error') || line.includes('Error:')) {
        parsedFrames.push({
          rawLine: line,
          isHeader: true,
          errorMessage: line
        });
      }
    }

    return parsedFrames;
  }

  const parser = {
    SourceMapConsumer,
    demapStackTrace
  };

  if (typeof window !== 'undefined') {
    window.SourceMapParser = parser;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = parser;
  }

  return parser;

})();
