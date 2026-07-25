'use strict';

// Reconstructs a real-world eval-on-input false positive (docs/REAL_WORLD_VALIDATION.md
// §5.4): validating a plugin/module name against an allowlist pattern using
// RegExp.prototype.exec(). No child_process import anywhere in this file at all -- just
// an ordinary regex-based name validator, the second of the three real-world .exec()
// shapes the validation exercise found (filename-number extraction, allowlist
// validation, scanning source text for a call signature).
const ALLOWED_PLUGIN_NAME_RE = /^[a-z][a-z0-9-]{0,63}$/;

function isAllowedPluginName(name) {
  return ALLOWED_PLUGIN_NAME_RE.exec(name) !== null;
}

function loadPlugin(pluginName, registry) {
  if (!isAllowedPluginName(pluginName)) {
    throw new Error(`Rejected plugin name "${pluginName}": does not match the allowed naming pattern.`);
  }
  return registry.get(pluginName);
}

module.exports = { isAllowedPluginName, loadPlugin };
