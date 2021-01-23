var utils = require('vaporyjs-util');
var inherits = require('util').inherits;
var StateManager = require('../statemanager.js');
var to = require('../utils/to');
var txhelper = require('../utils/txhelper');
var blockHelper = require('../utils/block_helper');
var pkg = require('../../package.json');
var _ = require('lodash');

var Subprovider = require('@vapormask/web3-provider-engine/subproviders/subprovider.js');

inherits(GvapApiDouble, Subprovider)

function GvapApiDouble(options, provider) {
  var self = this;

  this.state = options.state || new StateManager(options, provider);
  this.options = options;
  this.initialized = false;

  this.initialization_error = null;
  this.post_initialization_callbacks = [];

  this.state.initialize(function(err) {
    if (err) {
      self.initialization_error = err;
    }
    self.initialized = true;

    var callbacks = self.post_initialization_callbacks;
    self.post_initialization_callbacks = [];

    callbacks.forEach(function(callback) {
      setImmediate(function() {
        callback();
      });
    });
  });
}

GvapApiDouble.prototype.waitForInitialization = function(callback) {
  var self = this;
  if (self.initialized == false) {
    self.post_initialization_callbacks.push(callback);
  } else {
    callback(self.initialization_error, self.state);
  }
}

// Function to not pass methods through until initialization is finished
GvapApiDouble.prototype.handleRequest = function(payload, next, end) {
  var self = this;

  if (self.initialization_error != null) {
    return end(self.initialization_error);
  }

  if (self.initialized == false) {
    self.waitForInitialization(self.getDelayedHandler(payload, next, end));
    return;
  }

  var method = self[payload.method];

  if (method == null) {
    return end(new Error("Method " + payload.method + " not supported."));
  }

  var params = payload.params || [];
  var args = [].concat(params);

  var addedBlockParam = false;

  if (self.requiresDefaultBlockParameter(payload.method) && args.length < method.length - 1) {
    args.push("latest");
    addedBlockParam = true;
  }

  args.push(end);

  // avoid crash by checking to make sure that we haven't specified too many arguments
  if (
    args.length > method.length
    || (method.minLength !== undefined && args.length < method.minLength)
    || (method.minLength === undefined && args.length < method.length)
  ){

    var errorMessage = `Incorrect number of arguments. Method '${payload.method}' requires `;
    if (method.minLength) {
      errorMessage += `between ${method.minLength - 1} and ${method.length - 1} arguments. `;
    } else {
      errorMessage += `exactly ${method.length - 1} arguments. `;
    }

    if (addedBlockParam) {
      errorMessage += 'Including the implicit block argument, r';
    } else {
      // new sentence, capitalize it.
      errorMessage += 'R';
    }
    errorMessage += `equest specified ${args.length - 1} arguments: ${JSON.stringify(args)}.`

    return end(new Error(errorMessage));
  }

  method.apply(self, args);
};

GvapApiDouble.prototype.getDelayedHandler = function(payload, next, end) {
  var self = this;
  return function(err, state) {
    if (err) {
      end(err);
    }
    self.handleRequest(payload, next, end);
  }
}

GvapApiDouble.prototype.requiresDefaultBlockParameter = function(method) {
  // object for O(1) lookup.
  var methods = {
    "vap_getBalance": true,
    "vap_getCode": true,
    "vap_getTransactionCount": true,
    "vap_getStorageAt": true,
    "vap_call": true,
    "vap_estimateGas": true
  };

  return methods[method] === true;
};

// Handle individual requests.

GvapApiDouble.prototype.vap_accounts = function(callback) {
  callback(null, Object.keys(this.state.accounts));
};

GvapApiDouble.prototype.vap_blockNumber = function(callback) {
  this.state.blockNumber(function(err, result) {
    if (err) return callback(err);
    callback(null, to.hex(result));
  });
};

GvapApiDouble.prototype.vap_coinbase = function(callback) {
  callback(null, this.state.coinbase);
};

GvapApiDouble.prototype.vap_mining = function(callback) {
  callback(null, this.state.is_mining);
};

GvapApiDouble.prototype.vap_hashrate = function(callback) {
  callback(null, '0x0');
};

GvapApiDouble.prototype.vap_gasPrice = function(callback) {
  callback(null, utils.addHexPrefix(this.state.gasPrice()));
};

GvapApiDouble.prototype.vap_getBalance = function(address, block_number, callback) {
  this.state.getBalance(address, block_number, callback);
};

GvapApiDouble.prototype.vap_getCode = function(address, block_number, callback) {
  this.state.getCode(address, block_number, callback);
};

GvapApiDouble.prototype.vap_getBlockByNumber = function(block_number, include_full_transactions, callback) {
  this.state.blockchain.getBlock(block_number, function(err, block) {
    if (err) {
      if (err.message && err.message.indexOf("index out of range") >= 0) {
        return callback(null, null);
      } else {
        return callback(err);
      }
    }

    callback(null, blockHelper.toJSON(block, include_full_transactions));
  });
};

GvapApiDouble.prototype.vap_getBlockByHash = function(tx_hash, include_full_transactions, callback) {
  this.vap_getBlockByNumber.apply(this, arguments);
};

GvapApiDouble.prototype.vap_getBlockTransactionCountByNumber = function(block_number, callback) {
  this.state.blockchain.getBlock(block_number, function(err, block) {
    if (err) {
      if (err.message.indexOf("index out of range")) {
        // block doesn't exist
        return callback(null, 0);
      } else {
        return callback(err);
      }
    }
    callback(null, block.transactions.length);
  });
}

GvapApiDouble.prototype.vap_getBlockTransactionCountByHash = function(block_hash, callback) {
  this.vap_getBlockTransactionCountByNumber.apply(this, arguments);
}

GvapApiDouble.prototype.vap_getTransactionReceipt = function(hash, callback) {
  this.state.getTransactionReceipt(hash, function(err, receipt) {
    if (err) return callback(err);

    var result = null;

    if (receipt){
      result = receipt.toJSON();
    }
    callback(null, result);
  });
};

GvapApiDouble.prototype.vap_getTransactionByHash = function(hash, callback) {
  this.state.getTransactionReceipt(hash, function(err, receipt) {
    if (err) return callback(err);

    var result = null;

    if (receipt) {
      result = txhelper.toJSON(receipt.tx, receipt.block)
    }

    callback(null, result);
  });
}

GvapApiDouble.prototype.vap_getTransactionByBlockHashAndIndex = function(hash_or_number, index, callback) {
  var self = this;

  index = to.number(index);

  this.state.getBlock(hash_or_number, function(err, block) {
    if (err) {
      // block doesn't exist by that hash
      if (err.notFound) {
        return callback(null, null);
      } else {
        return callback(err);
      }
    }

    if (index >= block.transactions.length) {
      return callback(new Error("Transaction at index " + to.hex(index) + " does not exist in block."));
    }

    var tx = block.transactions[index];
    var result = txhelper.toJSON(tx, block);

    callback(null, result);
  });
};

GvapApiDouble.prototype.vap_getTransactionByBlockNumberAndIndex = function(hash_or_number, index, callback) {
  this.vap_getTransactionByBlockHashAndIndex(hash_or_number, index, callback);
};

GvapApiDouble.prototype.vap_getTransactionCount = function(address, block_number, callback) {
  this.state.getTransactionCount(address, block_number, callback);
}

GvapApiDouble.prototype.vap_sign = function(address, dataToSign, callback) {
  var result;
  var error;

  try {
    result = this.state.sign(address, dataToSign);
  } catch (e) {
    error = e;
  }

  callback(error, result);
};

GvapApiDouble.prototype.vap_sendTransaction = function(tx_data, callback) {
  this.state.queueTransaction("vap_sendTransaction", tx_data, null, callback);
};

GvapApiDouble.prototype.vap_sendRawTransaction = function(rawTx, callback) {
  this.state.queueRawTransaction(rawTx, callback);
};

GvapApiDouble.prototype.vap_call = function(tx_data, block_number, callback) {
  if (!tx_data.gas) {
    tx_data.gas = this.state.blockchain.blockGasLimit;
  }

  this.state.queueTransaction("vap_call", tx_data, block_number, callback); // :(
};

GvapApiDouble.prototype.vap_estimateGas = function(tx_data, block_number, callback) {
  if (!tx_data.gas) {
    tx_data.gas = this.state.blockchain.blockGasLimit;
  }
  this.state.queueTransaction("vap_estimateGas", tx_data, block_number, callback);
};

GvapApiDouble.prototype.vap_getStorageAt = function(address, position, block_number, callback) {
  this.state.queueStorage(address, position, block_number, callback);
};

GvapApiDouble.prototype.vap_newBlockFilter = function(callback) {
  var filter_id = utils.addHexPrefix(utils.intToHex(this.state.latest_filter_id));
  this.state.latest_filter_id += 1;
  callback(null, filter_id);
};

GvapApiDouble.prototype.vap_getFilterChanges = function(filter_id, callback) {
  var blockHash = this.state.latestBlock().hash().toString("hex");
  // Mine a block after each request to getFilterChanges so block filters work.
  this.state.mine();
  callback(null, [blockHash]);
};

GvapApiDouble.prototype.vap_getLogs = function(filter, callback) {
  this.state.getLogs(filter, callback);
};

GvapApiDouble.prototype.vap_uninstallFilter = function(filter_id, callback) {
  callback(null, true);
};

GvapApiDouble.prototype.vap_protocolVersion = function(callback) {
  callback(null, "63");
};

GvapApiDouble.prototype.bzz_hive = function(callback) {
  callback(null, []);
};

GvapApiDouble.prototype.bzz_info = function(callback) {
  callback(null, []);
};

GvapApiDouble.prototype.shh_version = function(callback) {
  callback(null, "2");
};

GvapApiDouble.prototype.vap_getCompilers = function(callback) {
  callback(null, ["solidity"]);
}

GvapApiDouble.prototype.vap_syncing = function(callback) {
  callback(null, false);
};

GvapApiDouble.prototype.net_listening = function(callback) {
  callback(null, true);
};

GvapApiDouble.prototype.net_peerCount = function(callback) {
  callback(null, 0);
};

GvapApiDouble.prototype.web3_clientVersion = function(callback) {
  callback(null, "VaporyJS TestRPC/v" + pkg.version + "/vapory-js")
};

GvapApiDouble.prototype.web3_sha3 = function(string, callback) {
  callback(null, to.hex(utils.sha3(string)));
};

GvapApiDouble.prototype.net_version = function(callback) {
  // net_version returns a string containing a base 10 integer.
  callback(null, this.state.net_version + "");
};

GvapApiDouble.prototype.miner_start = function(threads, callback) {
  if (!callback && typeof threads === 'function') {
    callback = threads;
    threads = null;
  }

  this.state.startMining(function(err) {
    callback(err, true);
  });
};

// indicate that `miner_start` only requires one argument (the callback)
GvapApiDouble.prototype.miner_start.minLength = 1;

GvapApiDouble.prototype.miner_stop = function(callback) {
  this.state.stopMining(function(err) {
    callback(err, true);
  });
};

GvapApiDouble.prototype.rpc_modules = function(callback) {
  // returns the availible api modules and versions
  callback(null, {"vap":"1.0","net":"1.0","rpc":"1.0","web3":"1.0","vvm":"1.0","personal":"1.0"});
};

GvapApiDouble.prototype.personal_listAccounts = function(callback) {
  callback(null, Object.keys(this.state.personal_accounts));
};

GvapApiDouble.prototype.personal_newAccount = function(password, callback) {
  var account = this.state.createAccount({ generate: true });
  this.state.accounts[account.address.toLowerCase()] = account;
  this.state.personal_accounts[account.address.toLowerCase()] = true;
  this.state.account_passwords[account.address.toLowerCase()] = password;
  callback(null, account.address);
};

GvapApiDouble.prototype.personal_importRawKey = function(rawKey, password, callback) {
  var account = this.state.createAccount({ secretKey: rawKey });
  this.state.accounts[account.address.toLowerCase()] = account;
  this.state.personal_accounts[account.address.toLowerCase()] = true;
  this.state.account_passwords[account.address.toLowerCase()] = password;
  callback(null, account.address);
};

GvapApiDouble.prototype.personal_lockAccount = function(address, callback) {
  var account = this.state.personal_accounts[address.toLowerCase()];
  if (account !== true) {
    return callback("Account not found");
  }
  delete this.state.unlocked_accounts[address.toLowerCase()];
  callback(null, true);
};

GvapApiDouble.prototype.personal_unlockAccount = function(address, password, duration, callback) {
  // FIXME handle duration
  var account = this.state.personal_accounts[address.toLowerCase()];
  if (account !== true) {
    return callback("Account not found");
  }

  var storedPassword = this.state.account_passwords[address.toLowerCase()];
  if (storedPassword !== undefined && storedPassword !== password) {
    return callback("Invalid password")
  }

  this.state.unlocked_accounts[address.toLowerCase()] = true;
  callback(null, true);
};

GvapApiDouble.prototype.personal_sendTransaction = function(tx_data, password, callback) {
  if (tx_data.from == null) {
    callback("Sender not found");
    return;
  }

  var from = utils.addHexPrefix(tx_data.from).toLowerCase();

  var self = this;
  self.personal_unlockAccount(from, password, null, function(err) {
    if (err) return callback(err);

    self.state.queueTransaction("vap_sendTransaction", tx_data, null, function(err, ret) {
      self.state.unlocked_accounts[from.toLowerCase()] = false;
      callback(err, ret);
    });
  });
};

/* Functions for testing purposes only. */

GvapApiDouble.prototype.vvm_snapshot = function(callback) {
  this.state.snapshot(callback)
};

GvapApiDouble.prototype.vvm_revert = function(snapshot_id, callback) {
  this.state.revert(snapshot_id, callback);
};

GvapApiDouble.prototype.vvm_increaseTime = function(seconds, callback) {
  callback(null, this.state.blockchain.increaseTime(seconds));
};

GvapApiDouble.prototype.vvm_mine = function(callback) {
  this.state.processBlocks(1, function(err) {
    callback(err, '0x0');
  });
};

GvapApiDouble.prototype.debug_traceTransaction = function(tx_hash, params, callback) {
  if (typeof params == "function") {
    callback = params;
    params = [];
  }

  this.state.queueTransactionTrace(tx_hash, params, callback);
};

module.exports = GvapApiDouble;
