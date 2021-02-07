var Subprovider = require('@vapormask/web3-provider-engine/subproviders/subprovider.js');
var inherits = require("util").inherits;

inherits(GvapDefaults, Subprovider);

module.exports = GvapDefaults;

function GvapDefaults() {};

// Massage vap_estimateGas requests, setting default data (e.g., from) if
// not specified. This is here specifically to make the testrpc
// react like Gvap.
GvapDefaults.prototype.handleRequest = function(payload, next, end) {
  var self = this;

  if (payload.method != "vap_estimateGas" && payload.method != "vap_call") {
    return next();
  }

  var params = payload.params[0];

  if (params.from == null) {
    this.emitPayload({
      method: "vap_coinbase"
    }, function(err, result) {
      if (err) return end(err);

      var coinbase = result.result;

      params.from = coinbase;
      next();
    });
  } else {
    next();
  }
};
