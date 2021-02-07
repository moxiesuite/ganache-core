var ProviderEngine = require("@vapormask/web3-provider-engine");
var FilterSubprovider = require('@vapormask/web3-provider-engine/subproviders/filters.js');
//var SolcSubprovider = require('@vapormask/web3-provider-engine/subproviders/solc.js')

var BlockchainDouble = require('./blockchain_double.js');

var RequestFunnel = require('./subproviders/requestfunnel.js');
var DelayedBlockFilter = require("./subproviders/delayedblockfilter.js");
var ReactiveBlockTracker = require("./subproviders/reactiveblocktracker.js");
var GvapDefaults = require("./subproviders/gvapdefaults.js");
var GvapApiDouble = require('./subproviders/gvap_api_double.js');

var RuntimeError = require("./utils/runtimeerror");

function Provider(options) {
  var self = this;

  if (options == null) {
    options = {};
  }

  if (options.logger == null) {
    options.logger = {
      log: function() {}
    };
  }

  this.options = options;
  this.engine = new ProviderEngine();

  var gvapApiDouble = new GvapApiDouble(options);

  this.engine.manager = gvapApiDouble;
  this.engine.addProvider(new RequestFunnel());
  this.engine.addProvider(new ReactiveBlockTracker());
  this.engine.addProvider(new DelayedBlockFilter());
  this.engine.addProvider(new FilterSubprovider());
  this.engine.addProvider(new GvapDefaults());
  this.engine.addProvider(gvapApiDouble);

  this.engine.setMaxListeners(100);
  this.engine.start();

  this.manager = gvapApiDouble;
};

Provider.prototype.sendAsync = function(payload, callback) {
  var self = this;

  var externalize = function(payload) {
    var clone = {};
    var keys = Object.keys(payload);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      clone[key] = payload[key];
    }
    clone.external = true;
    return clone;
  };

  if (Array.isArray(payload)) {
    for (var i = 0; i < payload.length; i++) {
      payload[i] = externalize(payload[i]);
    }
  } else {
    payload = externalize(payload);
  }

  var intermediary = function(err, result) {
    if (err) {
      // If we find a runtime error, mimic the result that would be sent back from
      // normal Vapory clients that don't return runtime errors (e.g., gvap, parity).
      if (err instanceof RuntimeError && (payload.method == "vap_sendTransaction" || payload.method == "vap_sendRawTransaction")) {
        result.result = err.hashes[0];
      }
    } else if (self.options.verbose) {
      self.options.logger.log(" <   " + JSON.stringify(result, null, 2).split("\n").join("\n <   "));
    }
    callback(err, result);
  };

  if (self.options.verbose) {
    self.options.logger.log("   > " + JSON.stringify(payload, null, 2).split("\n").join("\n   > "));
  }

  this.engine.sendAsync(payload, intermediary);
};

Provider.prototype.send = function() {
  throw new Error("Synchronous requests are not supported.");
};

Provider.prototype.close = function(callback) {
  // This is a little gross reaching, but...
  this.manager.state.blockchain.close(callback);
};

module.exports = Provider;
