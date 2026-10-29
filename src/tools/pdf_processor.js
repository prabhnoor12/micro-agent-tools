/**
 * PDFProcessor Agent Tool
 * Headless PDF merging, vector form-filling, checkbox stamping & metadata inspection
 * Cost: $0.005 / call
 */

const { PDFDocument, rgb, StandardFonts, degrees } = require('pdf-lib');

const MAX_PAGES = 100;
const MAX_DECODED_BYTES = 8 * 1024 * 1024;
const MAX_FIELD_TEXT = 500;
const ALLOWED_ROTATIONS = new Set([0, 90, 180, 270]);

function fail413(message) {
  const err = new Error(message);
  err.statusCode = 413;
  throw err;
}

function decodePdfInput(item) {
  const bytes = Buffer.isBuffer(item)
    ? item
    : Buffer.from(String(item).replace(/^data:application\/pdf;base64,/, ''), 'base64');
  if (bytes.length > MAX_DECODED_BYTES) fail413('PDF exceeds max decoded size of 8MB.');
  if (bytes.length < 5 || bytes.slice(0, 5).toString('ascii') !== '%PDF-') {
    const err = new Error('Invalid PDF: missing %PDF header.');
    err.statusCode = 400;
    throw err;
  }
  return bytes;
}

async function loadPdf(bytes) {
  try {
    // ignoreEncryption defaults to false: encrypted PDFs throw instead of
    // silently decrypting with an empty password.
    return await PDFDocument.load(bytes);
  } catch (err) {
    if (err && err.statusCode) throw err;
    const e = new Error('Invalid or encrypted PDF: unable to parse.');
    e.statusCode = 400;
    throw e;
  }
}

function checkRotation(rotation) {
  if (!ALLOWED_ROTATIONS.has(rotation)) {
    const err = new Error('"rotation" must be one of 0, 90, 180, 270.');
    err.statusCode = 400;
    throw err;
  }
}

function checkFields(fields) {
  if (!Array.isArray(fields)) {
    const err = new Error('"fields" must be an array.');
    err.statusCode = 400;
    throw err;
  }
  for (const f of fields) {
    if (!f || typeof f !== 'object') {
      const err = new Error('Each field must be an object.');
      err.statusCode = 400;
      throw err;
    }
    if (f.type !== undefined && !['text', 'check', 'cross'].includes(f.type)) {
      const err = new Error('Field "type" must be text, check, or cross.');
      err.statusCode = 400;
      throw err;
    }
    if (f.text !== undefined && String(f.text).length > MAX_FIELD_TEXT) {
      fail413('Field "text" exceeds max length of 500 chars.');
    }
    for (const k of ['x_percent', 'y_percent']) {
      if (f[k] !== undefined && (typeof f[k] !== 'number' || f[k] < 0 || f[k] > 1)) {
        const err = new Error(`Field "${k}" must be a number between 0 and 1.`);
        err.statusCode = 400;
        throw err;
      }
    }
    if (f.font_size !== undefined && (typeof f.font_size !== 'number' || f.font_size < 6 || f.font_size > 72)) {
      const err = new Error('Field "font_size" must be between 6 and 72.');
      err.statusCode = 400;
      throw err;
    }
    if (f.color !== undefined && !['black', 'blue', 'red'].includes(f.color)) {
      const err = new Error('Field "color" must be black, blue, or red.');
      err.statusCode = 400;
      throw err;
    }
  }
}

async function execute(args, opts = {}) {
  const signal = opts.signal || null;
  const checkAborted = () => {
    if (signal && signal.aborted) {
      const err = new Error('PDF processing aborted (timeout).');
      err.statusCode = 504;
      throw err;
    }
  };
  const { mode = 'inspect', pdf_base64, pdf_list = [], fields = [], rotation = 0 } = args;

  // 1. Mode: Merge
  if (mode === 'merge') {
    if (!pdf_list || pdf_list.length === 0) {
      throw new Error('"pdf_list" array of base64 strings or buffer objects is required for merge mode.');
    }
    checkRotation(rotation);

    const mergedDoc = await PDFDocument.create();
    let totalPagesMerged = 0;

    for (const item of pdf_list) {
      checkAborted();
      const bytes = decodePdfInput(item);
      const srcDoc = await loadPdf(bytes);
      if (srcDoc.getPageCount() > MAX_PAGES) fail413(`Source PDF exceeds max of ${MAX_PAGES} pages.`);
      const pageIndices = srcDoc.getPageIndices();
      const copiedPages = await mergedDoc.copyPages(srcDoc, pageIndices);
      copiedPages.forEach(p => {
        if (rotation) p.setRotation(degrees(rotation));
        mergedDoc.addPage(p);
        totalPagesMerged++;
        if (totalPagesMerged > MAX_PAGES) fail413(`Merged PDF exceeds max of ${MAX_PAGES} pages.`);
      });
    }

    const outputBytes = await mergedDoc.save();
    return {
      success: true,
      mode: 'merge',
      total_pages: totalPagesMerged,
      pdf_base64: Buffer.from(outputBytes).toString('base64'),
      size_bytes: outputBytes.length
    };
  }

  // 2. Mode: Fill Fields / Annotate
  if (mode === 'fill') {
    if (!pdf_base64) {
      throw new Error('"pdf_base64" string is required for fill mode.');
    }
    checkFields(fields);

    const rawBytes = decodePdfInput(pdf_base64);
    const doc = await loadPdf(rawBytes);
    const font = await doc.embedFont(StandardFonts.Helvetica);
    const fontBold = await doc.embedFont(StandardFonts.HelveticaBold);

    const numPages = doc.getPageCount();
    if (numPages > MAX_PAGES) fail413(`PDF exceeds max of ${MAX_PAGES} pages.`);
    checkAborted();
    let annotationsApplied = 0;

    for (const field of fields) {
      const pageIndex = Math.max(0, Math.min(numPages - 1, (field.page || 1) - 1));
      const page = doc.getPage(pageIndex);
      const { width, height } = page.getSize();

      const fontSize = field.font_size || 12;
      const x = (field.x_percent !== undefined ? field.x_percent : 0.1) * width;
      const y = (1 - (field.y_percent !== undefined ? field.y_percent : 0.1)) * height - fontSize;

      let color = rgb(0.1, 0.12, 0.15);
      if (field.color === 'blue') color = rgb(0.01, 0.4, 0.8);
      else if (field.color === 'red') color = rgb(0.9, 0.1, 0.2);

      if (field.type === 'check') {
        // Draw vector checkmark lines (immune to font encoding)
        page.drawLine({
          start: { x: x, y: y + fontSize * 0.3 },
          end: { x: x + fontSize * 0.35, y: y },
          thickness: 2,
          color
        });
        page.drawLine({
          start: { x: x + fontSize * 0.35, y: y },
          end: { x: x + fontSize * 0.85, y: y + fontSize * 0.8 },
          thickness: 2,
          color
        });
      } else if (field.type === 'cross') {
        // Draw vector cross mark
        page.drawLine({ start: { x, y }, end: { x: x + fontSize * 0.8, y: y + fontSize * 0.8 }, thickness: 2, color });
        page.drawLine({ start: { x, y: y + fontSize * 0.8 }, end: { x: x + fontSize * 0.8, y }, thickness: 2, color });
      } else {
        page.drawText(String(field.text || ''), { x, y, size: fontSize, font, color });
      }
      annotationsApplied++;
    }

    const outputBytes = await doc.save();
    return {
      success: true,
      mode: 'fill',
      annotations_count: annotationsApplied,
      total_pages: numPages,
      pdf_base64: Buffer.from(outputBytes).toString('base64'),
      size_bytes: outputBytes.length
    };
  }

  // 3. Mode: Inspect / Sample Generator
  if (mode === 'sample') {
    const doc = await PDFDocument.create();
    const page = doc.addPage([595.28, 841.89]);
    const fontBold = await doc.embedFont(StandardFonts.HelveticaBold);
    const font = await doc.embedFont(StandardFonts.Helvetica);

    page.drawText('AUTONOMOUS AGENT DOCUMENT', { x: 50, y: 780, size: 16, font: fontBold, color: rgb(0.1, 0.15, 0.25) });
    page.drawText('Generated by MicroAgent PDF Engine.', { x: 50, y: 755, size: 10, font, color: rgb(0.4, 0.45, 0.5) });
    page.drawLine({ start: { x: 50, y: 740 }, end: { x: 545, y: 740 }, thickness: 1, color: rgb(0.8, 0.85, 0.9) });

    page.drawText('Field 1 (Name): ________________________________', { x: 50, y: 700, size: 11, font, color: rgb(0.2, 0.25, 0.3) });
    page.drawText('Field 2 (Date): ________________________________', { x: 50, y: 660, size: 11, font, color: rgb(0.2, 0.25, 0.3) });

    const outputBytes = await doc.save();
    return {
      success: true,
      mode: 'sample',
      total_pages: 1,
      pdf_base64: Buffer.from(outputBytes).toString('base64'),
      size_bytes: outputBytes.length
    };
  }

  // Default: Inspect
  if (!pdf_base64) {
    throw new Error('"pdf_base64" parameter is required to inspect PDF.');
  }
  const rawBytes = decodePdfInput(pdf_base64);
  const doc = await loadPdf(rawBytes);
  const pageCount = doc.getPageCount();
  if (pageCount > MAX_PAGES) fail413(`PDF exceeds max of ${MAX_PAGES} pages.`);
  const firstPage = doc.getPage(0);
  const { width, height } = firstPage.getSize();

  return {
    success: true,
    mode: 'inspect',
    page_count: pageCount,
    first_page_dimensions: { width, height },
    title: doc.getTitle() || null,
    author: doc.getAuthor() || null
  };
}

module.exports = {
  name: 'pdf_processor',
  description: 'Headless PDF engine: merges multiple PDFs, fills flat form fields at exact coordinate percentages, stamps checkmarks, and inspects page counts.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      mode: { type: 'string', enum: ['merge', 'fill', 'inspect', 'sample'], description: 'Operation mode. Default "inspect".' },
      pdf_base64: { type: 'string', description: 'Base64 encoded PDF string' },
      pdf_list: { type: 'array', items: { type: 'string' }, description: 'Array of base64 PDF strings for "merge" mode' },
      fields: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            page: { type: 'number', description: '1-indexed page number' },
            type: { type: 'string', enum: ['text', 'check', 'cross'], description: 'Field type' },
            text: { type: 'string', description: 'Text to write' },
            x_percent: { type: 'number', description: 'Horizontal position ratio (0.0 to 1.0)' },
            y_percent: { type: 'number', description: 'Vertical position ratio (0.0 to 1.0)' },
            font_size: { type: 'number', description: 'Font size in points. Default 12.' },
            color: { type: 'string', enum: ['black', 'blue', 'red'] }
          }
        },
        description: 'Array of fields and checkmarks to stamp onto PDF'
      },
      rotation: { type: 'number', description: 'Optional rotation in degrees (90, 180, 270) for merged pages' }
    }
  },
  execute
};
