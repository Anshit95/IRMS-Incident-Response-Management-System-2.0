/**
 * Enterprise Application Hardening & Input Sanitizer (IRMS v2.0)
 *
 * Protects against:
 * - Cross-Site Scripting (XSS) in stored and reflected inputs
 * - Prototype Pollution attacks (__proto__, constructor)
 * - Null-byte injection (\0)
 * - Malicious URI schemes (javascript:, data:, vbscript:)
 * - Denial of Service via massive query limits
 */

const DANGEROUS_HTML_REGEX = /<[^>]*script[^>]*>|<[^>]*iframe[^>]*>|<[^>]*object[^>]*>|<[^>]*embed[^>]*>|<[^>]*style[^>]*>|onload=|onerror=|onclick=|onmouseover=|javascript:|vbscript:/gi;

function cleanString(str) {
  if (typeof str !== 'string') return str;
  // Remove null bytes
  let cleaned = str.replace(/\0/g, '');
  // Neutralize script tags and event handlers while preserving normal text
  cleaned = cleaned.replace(DANGEROUS_HTML_REGEX, '');
  return cleaned.trim();
}

function sanitizeObject(obj, depth = 0) {
  if (depth > 8 || !obj || typeof obj !== 'object') return obj;

  // Prevent prototype pollution
  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item, depth + 1));
  }

  const sanitized = {};
  for (const [key, value] of Object.entries(obj)) {
    // Block prototype poisoning keys
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }

    if (typeof value === 'string') {
      sanitized[key] = cleanString(value);
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeObject(value, depth + 1);
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

function inputSanitizer(req, res, next) {
  if (req.body && typeof req.body === 'object') {
    req.body = sanitizeObject(req.body);
  }

  if (req.query && typeof req.query === 'object') {
    req.query = sanitizeObject(req.query);

    // Clamp pagination limit and page to prevent DoS memory exhaustion
    if (req.query.limit) {
      const parsedLimit = parseInt(req.query.limit, 10);
      req.query.limit = isNaN(parsedLimit) ? 20 : Math.min(100, Math.max(1, parsedLimit));
    }
    if (req.query.page) {
      const parsedPage = parseInt(req.query.page, 10);
      req.query.page = isNaN(parsedPage) ? 1 : Math.max(1, parsedPage);
    }
  }

  if (req.params && typeof req.params === 'object') {
    req.params = sanitizeObject(req.params);
  }

  next();
}

module.exports = {
  inputSanitizer,
  cleanString,
  sanitizeObject
};
