var utils = require("vaporyjs-util");
var inherits = require("util").inherits;
var StateManager = require("../statemanager.js");
var to = require("../utils/to");
var TXRejectedError = require("../utils/txrejectederror");

var blockHelper = require("../utils/block_helper");
var pkg = require("../../package.json");
const { BlockOutOfRangeError } = require("../utils/errorhelper");

var Subprovider = require("web3-provider-engine/subproviders/subprovider.js");

inherits(GvapApiDouble, Subprovider);

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
        callback(self.initialization_error, self.state);
      });
    });
  });
}

GvapApiDouble.prototype.waitForInitialization = function(callback) {
  var self = this;
  if (self.initialized === false) {
    self.post_initialization_callbacks.push(callback);
  } else {
    callback(self.initialization_error, self.state);
  }
};

// Function to not pass methods through until initialization is finished
GvapApiDouble.prototype.handleRequest = function(payload, next, end) {
  var self = this;

  if (self.initialization_error != null) {
    return end(self.initialization_error);
  }

  if (self.initialized === false) {
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
    args.length > method.length ||
    (method.minLength !== undefined && args.length < method.minLength) ||
    (method.minLength === undefined && args.length < method.length)
  ) {
    var errorMessage = `Incorrect number of arguments. Method '${payload.method}' requires `;
    if (method.minLength) {
      errorMessage += `between ${method.minLength - 1} and ${method.length - 1} arguments. `;
    } else {
      errorMessage += `exactly ${method.length - 1} arguments. `;
    }

    if (addedBlockParam) {
      errorMessage += "Including the implicit block argument, r";
    } else {
      // new sentence, capitalize it.
      errorMessage += "R";
    }
    errorMessage += `equest specified ${args.length - 1} arguments: ${JSON.stringify(args)}.`;

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
  };
};

GvapApiDouble.prototype.requiresDefaultBlockParameter = function(method) {
  // object for O(1) lookup.
  var methods = {
    vap_getBalance: true,
    vap_getCode: true,
    vap_getTransactionCount: true,
    vap_getStorageAt: true,
    vap_call: true,
    vap_estimateGas: true
  };

  return methods[method] === true;
};

// Handle individual requests.

GvapApiDouble.prototype.vap_accounts = function(callback) {
  callback(null, Object.keys(this.state.accounts));
};

GvapApiDouble.prototype.vap_blockNumber = function(callback) {
  this.state.blockNumber(function(err, result) {
    if (err) {
      return callback(err);
    }
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
  callback(null, "0x0");
};

GvapApiDouble.prototype.vap_gasPrice = function(callback) {
  callback(null, utils.addHexPrefix(this.state.gasPrice()));
};

GvapApiDouble.prototype.vap_getBalance = function(address, blockNumber, callback) {
  this.state.getBalance(address, blockNumber, callback);
};

GvapApiDouble.prototype.vap_getCode = function(address, blockNumber, callback) {
  this.state.getCode(address, blockNumber, callback);
};

GvapApiDouble.prototype.vap_getBlockByNumber = function(blockNumber, includeFullTransactions, callback) {
  this.state.blockchain.getBlock(blockNumber, function(err, block) {
    if (err) {
      if (err.message && err.message.indexOf("index out of range") >= 0) {
        return callback(null, null);
      } else {
        return callback(err);
      }
    }

    callback(null, blockHelper.toJSON(block, includeFullTransactions));
  });
};

GvapApiDouble.prototype.vap_getBlockByHash = function(txHash, includeFullTransactions, callback) {
  this.vap_getBlockByNumber.apply(this, arguments);
};

GvapApiDouble.prototype.vap_getBlockTransactionCountByNumber = function(blockNumber, callback) {
  this.state.blockchain.getBlock(blockNumber, function(err, block) {
    if (err) {
      if (err instanceof BlockOutOfRangeError) {
        // block doesn't exist
        return callback(null, 0);
      }
      return callback(err);
    }
    callback(null, block.transactions.length);
  });
};

GvapApiDouble.prototype.vap_getBlockTransactionCountByHash = function(blockHash, callback) {
  this.vap_getBlockTransactionCountByNumber.apply(this, arguments);
};

GvapApiDouble.prototype.vap_getTransactionReceipt = function(hash, callback) {
  this.state.getTransactionReceipt(hash, function(err, receipt) {
    if (err) {
      return callback(err);
    }

    var result = null;

    if (receipt) {
      result = receipt.toJSON();
    }
    callback(null, result);
  });
};

GvapApiDouble.prototype.vap_getTransactionByHash = function(hash, callback) {
  this.state.getTransactionReceipt(hash, function(err, receipt) {
    if (err) {
      return callback(err);
    }

    var result = null;

    if (receipt) {
      result = receipt.tx.toJsonRpc(receipt.block);
    }

    callback(null, result);
  });
};

GvapApiDouble.prototype.vap_getTransactionByBlockHashAndIndex = function(hashOrNumber, index, callback) {
  index = to.number(index);

  this.state.getBlock(hashOrNumber, function(err, block) {
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
    var result = tx.toJsonRpc(block);

    callback(null, result);
  });
};

GvapApiDouble.prototype.vap_getTransactionByBlockNumberAndIndex = function(hashOrNumber, index, callback) {
  this.vap_getTransactionByBlockHashAndIndex(hashOrNumber, index, callback);
};

GvapApiDouble.prototype.vap_getTransactionCount = function(address, blockNumber, callback) {
  this.state.getTransactionCount(address, blockNumber, (err, count) => {
    if (err && err.message && err.message.indexOf("index out of range") >= 0) {
      err = new Error("Unknown block number");
    }
    return callback(err, count);
  });
};

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

GvapApiDouble.prototype.vap_signTypedData = function(address, typedDataToSign, callback) {
  var result;
  var error;

  try {
    result = this.state.signTypedData(address, typedDataToSign);
  } catch (e) {
    error = e;
  }

  callback(error, result);
};

GvapApiDouble.prototype.vap_sendTransaction = function(txData, callback) {
  this.state.queueTransaction("vap_sendTransaction", txData, null, callback);
};

GvapApiDouble.prototype.vap_sendRawTransaction = function(rawTx, callback) {
  let data;
  if (rawTx) {
    data = to.buffer(rawTx);
  }

  if (data === undefined) {
    throw new TXRejectedError("rawTx must be a string, JSON-encoded Buffer, or Buffer.");
  }

  this.state.queueRawTransaction(data, callback);
};

GvapApiDouble.prototype.vap_call = function(txData, blockNumber, callback) {
  if (!txData.gas) {
    txData.gas = this.state.blockchain.blockGasLimit;
  }

  this.state.queueTransaction("vap_call", txData, blockNumber, callback); // :(
};

GvapApiDouble.prototype.vap_estimateGas = function(txData, blockNumber, callback) {
  if (!txData.gas) {
    txData.gas = this.state.blockchain.blockGasLimit;
  }
  this.state.queueTransaction("vap_estimateGas", txData, blockNumber, callback);
};

GvapApiDouble.prototype.vap_getStorageAt = function(address, position, blockNumber, callback) {
  this.state.queueStorage(address, position, blockNumber, callback);
};

GvapApiDouble.prototype.vap_newBlockFilter = function(callback) {
  var filterId = utils.addHexPrefix(utils.intToHex(this.state.latestFilterId));
  this.state.latestFilterId += 1;
  callback(null, filterId);
};

GvapApiDouble.prototype.vap_getFilterChanges = function(filterId, callback) {
  var blockHash = this.state
    .latestBlock()
    .hash()
    .toString("hex");
  // Mine a block after each request to getFilterChanges so block filters work.
  this.state.mine();
  callback(null, [blockHash]);
};

GvapApiDouble.prototype.vap_getLogs = function(filter, callback) {
  this.state.getLogs(filter, callback);
};

GvapApiDouble.prototype.vap_uninstallFilter = function(filterId, callback) {
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
  callback(null, []);
};

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
  callback(null, "VaporyJS TestRPC/v" + pkg.version + "/vapory-js");
};

GvapApiDouble.prototype.web3_sha3 = function(string, callback) {
  callback(null, to.hex(utils.sha3(string)));
};

GvapApiDouble.prototype.net_version = function(callback) {
  // net_version returns a string containing a base 10 integer.
  callback(null, this.state.net_version + "");
};

GvapApiDouble.prototype.miner_start = function(threads, callback) {
  if (!callback && typeof threads === "function") {
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
  callback(null, { vap: "1.0", net: "1.0", rpc: "1.0", web3: "1.0", vvm: "1.0", personal: "1.0" });
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
    var error = "Account not found";
    return callback(error);
  }
  delete this.state.unlocked_accounts[address.toLowerCase()];
  callback(null, true);
};

GvapApiDouble.prototype.personal_unlockAccount = function(address, password, duration, callback) {
  // FIXME handle duration
  var account = this.state.personal_accounts[address.toLowerCase()];
  if (account !== true) {
    var accountError = "Account not found";
    return callback(accountError);
  }

  var storedPassword = this.state.account_passwords[address.toLowerCase()];
  if (storedPassword !== undefined && storedPassword !== password) {
    var passwordError = "Invalid password";
    return callback(passwordError);
  }

  this.state.unlocked_accounts[address.toLowerCase()] = true;
  callback(null, true);
};

GvapApiDouble.prototype.personal_sendTransaction = function(txData, password, callback) {
  if (txData.from == null) {
    var error = "Sender not found";
    callback(error);
    return;
  }

  var from = utils.addHexPrefix(txData.from).toLowerCase();

  var self = this;
  self.personal_unlockAccount(from, password, null, function(err) {
    if (err) {
      return callback(err);
    }

    self.state.queueTransaction("vap_sendTransaction", txData, null, function(err, ret) {
      self.state.unlocked_accounts[from.toLowerCase()] = false;
      callback(err, ret);
    });
  });
};

/* Functions for testing purposes only. */

GvapApiDouble.prototype.vvm_snapshot = function(callback) {
  this.state.snapshot(callback);
};

GvapApiDouble.prototype.vvm_revert = function(snapshotId, callback) {
  this.state.revert(snapshotId, callback);
};

GvapApiDouble.prototype.vvm_increaseTime = function(seconds, callback) {
  callback(null, this.state.blockchain.increaseTime(seconds));
};

GvapApiDouble.prototype.vvm_setTime = function(date, callback) {
  callback(null, this.state.blockchain.setTime(date));
};

GvapApiDouble.prototype.vvm_mine = function(timestamp, callback) {
  if (typeof timestamp === "function") {
    callback = timestamp;
    timestamp = undefined;
  }
  this.state.processBlock(timestamp, function(err) {
    if (err) {
      return callback(err);
    }
    callback(err, "0x0");
  });
};

// indicate that `vvm_mine` only requires one argument (the callback)
GvapApiDouble.prototype.vvm_mine.minLength = 1;

GvapApiDouble.prototype.debug_traceTransaction = function(txHash, params, callback) {
  if (typeof params === "function") {
    callback = params;
    params = [];
  }

  this.state.queueTransactionTrace(txHash, params, callback);
};

/*
  RPC AUDIT:
  TODO VAP: vap_getUncleCountByBlockHash, vap_getUncleCountByBlockNumber, vap_getUncleByBlockHashAndIndex,
        vap_getUncleByBlockNumberAndIndex, vap_getWork, vap_submitWork, vap_submitHashrate

  TODO DB: db_putString, db_getString, db_putHex, db_getHex

  TODO WHISPER: shh_post, shh_newIdentity, shh_hasIdentity, shh_newGroup, shh_addToGroup,
        shh_newFilter, shh_uninstallFilter, shh_getFilterChanges, shh_getMessages
*/

/**
 * Returns the number of uncles in a block from a block matching the given block hash.
 *
 * @param {DATA, 32 Bytes} hash - hash of a block.
 * @callback callback
 * @param {error} err - Error Object
 * @param {QUANTITY} result - integer of the number of uncles in this block.
 */
GvapApiDouble.prototype.vap_getUncleCountByBlockHash = function(hash, callback) {
  callback(null, "0x0");
};

/**
 * Returns the number of uncles in a block from a block matching the given block number.
 *
 * @param {QUANTITY} blockNumber -
 *  ^integer of a block number, or the string "latest", "earliest" or "pending". Ex: '0xe8', // 232
 * @callback callback
 * @param {error} err - Error Object
 * @param {QUANTITY} result - integer of the number of uncles in this block.
 */
GvapApiDouble.prototype.vap_getUncleCountByBlockNumber = function(blockNumber, callback) {
  callback(null, "0x0");
};

/**
 * Returns information about a uncle of a block by hash and uncle index position.
 *
 * @param {DATA, 32 Bytes} hash - hash of a block
 * @param {QUANTITY} index - the uncle's index position.
 * @callback callback
 * @param {error} err - Error Object
 * @param {Object} result - A block object,
 */
GvapApiDouble.prototype.vap_getUncleByBlockHashAndIndex = function(hash, index, callback) {
  callback(null, {});
};

/**
 * Returns information about a uncle of a block by number and uncle index position.
 *
 * @param {QUANTITY} blockNumber -
 * ^a block number, or the string "earliest", "latest" or "pending", as in the default block parameter.
 * @param {QUANTITY} uncleIndex - the uncle's index position.
 * @callback callback
 * @param {error} err - Error object
 * @param {Object} resutl - A block object,
 */
GvapApiDouble.prototype.vap_getUncleByBlockNumberAndIndex = function(blockNumber, uncleIndex, callback) {
  callback(null, {});
};

/**
 * Returns: An Array with the following elements
 * 1: DATA, 32 Bytes - current block header pow-hash
 * 2: DATA, 32 Bytes - the seed hash used for the DAG.
 * 3: DATA, 32 Bytes - the boundary condition ("target"), 2^256 / difficulty.
 *
 * @param {QUANTITY} filterId - A filter id
 * @callback callback
 * @param {error} err - Error object
 * @param {Array} result - the hash of the current block, the seedHash, and the boundary condition to be met ("target").
 */
GvapApiDouble.prototype.vap_getWork = function(filterId, callback) {
  callback(null, []);
};

/**
 * Used for submitting a proof-of-work solution
 *
 * @param {DATA, 8 Bytes} nonce - The nonce found (64 bits)
 * @param {DATA, 32 Bytes} powHash - The header's pow-hash (256 bits)
 * @param {DATA, 32 Bytes} digest - The mix digest (256 bits)
 * @callback callback
 * @param {error} err - Error object
 * @param {Boolean} result - returns true if the provided solution is valid, otherwise false.
 */
GvapApiDouble.prototype.vap_submitWork = function(nonce, powHash, digest, callback) {
  callback(null, false);
};

/**
 * Used for submitting mining hashrate.
 *
 * @param {String} hashRate - a hexadecimal string representation (32 bytes) of the hash rate
 * @param {String} clientID - A random hexadecimal(32 bytes) ID identifying the client
 * @callback callback
 * @param {error} err - Error object
 * @param {Boolean} result - returns true if submitting went through succesfully and false otherwise.
 */
GvapApiDouble.prototype.vap_submitHashrate = function(hashRate, clientID, callback) {
  callback(null, false);
};

/**
 * Stores a string in the local database.
 *
 * @param {String} dbName - Database name.
 * @param {String} key - Key name.
 * @param {String} value - String to store.
 * @callback callback
 * @param {error} err - Error object
 * @param {Boolean} result - returns true if the value was stored, otherwise false.
 */
GvapApiDouble.prototype.db_putString = function(dbName, key, value, callback) {
  callback(null, false);
};

/**
 * Returns string from the local database
 *
 * @param {String} dbName - Database name.
 * @param {String} key - Key name.
 * @callback callback
 * @param {error} - Error Object
 * @param {String} result - The previously stored string.
 */
GvapApiDouble.prototype.db_getString = function(dbName, key, callback) {
  callback(null, "");
};

/**
 * Stores binary data in the local database.
 *
 * @param {String} dbName - Database name.
 * @param {String} key - Key name.
 * @param {DATA} data - Data to store.
 * @callback callback
 * @param {error} err - Error Object
 * @param {Boolean} result - returns true if the value was stored, otherwise false.
 */
GvapApiDouble.prototype.db_putHex = function(dbName, key, data, callback) {
  callback(null, false);
};

/**
 * Returns binary data from the local database
 *
 * @param {String} dbName - Database name.
 * @param {String} key - Key name.
 * @callback callback
 * @param {error} err - Error Object
 * @param {DATA} result - The previously stored data.
 */
GvapApiDouble.prototype.db_getHex = function(dbName, key, callback) {
  callback(null, "0x00");
};

/**
 * Sends a whisper message.
 *
 * @param {DATA, 60 Bytes} from - (optional) The identity of the sender.
 * @param {DATA, 60 Bytes} to -
 *  ^(optional) The identity of the receiver. When present whisper will encrypt the message so that
 *  only the receiver can decrypt it.
 * @param {Array of DATA} topics - Array of DATA topics, for the receiver to identify messages.
 * @param {DATA} payload - The payload of the message.
 * @param {QUANTITY} priority - The integer of the priority in a range from ... (?).
 * @param {QUANTITY} ttl - integer of the time to live in seconds.
 * @callback callback
 * @param {error} err - Error Object
 * @param {Boolean} result - returns true if the message was sent, otherwise false.
 */
GvapApiDouble.prototype.shh_post = function(from, to, topics, payload, priority, ttl, callback) {
  callback(null, false);
};

/**
 * Creates new whisper identity in the client.
 *
 * @callback callback
 * @param {error} err - Error Object
 * @param {DATA, 60 Bytes} result - the address of the new identiy.
 */
GvapApiDouble.prototype.shh_newIdentity = function(callback) {
  callback(null, "0x00");
};

/**
 * Checks if the client hold the private keys for a given identity.
 *
 * @param {DATA, 60 Bytes} address - The identity address to check.
 * @callback callback
 * @param {error} err - Error Object
 * @param {Boolean} result - returns true if the client holds the privatekey for that identity, otherwise false.
 */
GvapApiDouble.prototype.shh_hasIdentity = function(address, callback) {
  callback(null, false);
};

/**
 * Creates a new group.
 *
 * @callback callback
 * @param {error} err - Error Object
 * @param {DATA, 60 Bytes} result - the address of the new group.
 */
GvapApiDouble.prototype.shh_newGroup = function(callback) {
  callback(null, "0x00");
};

/**
 * Adds a whisper identity to the group
 *
 * @param {DATA, 60 Bytes} - The identity address to add to a group.
 * @callback callback
 * @param {error} err - Error Object
 * @param {Boolean} result - returns true if the identity was successfully added to the group, otherwise false.
 */
GvapApiDouble.prototype.shh_addToGroup = function(address, callback) {
  callback(null, false);
};

/**
 * Creates filter to notify, when client receives whisper message matching the filter options.
 *
 * @param {DATA, 60 Bytes} to -
 * ^(optional) Identity of the receiver. When present it will try to decrypt any incoming message
 *  if the client holds the private key to this identity.
 * @param {Array of DATA} topics - Array of DATA topics which the incoming message's topics should match.
 * @callback callback
 * @param {error} err - Error Object
 * @param {Boolean} result - returns true if the identity was successfully added to the group, otherwise false.
 */
GvapApiDouble.prototype.shh_newFilter = function(to, topics, callback) {
  callback(null, false);
};

/**
 * Uninstalls a filter with given id. Should always be called when watch is no longer needed.
 * Additonally Filters timeout when they aren't requested with shh_getFilterChanges for a period of time.
 *
 * @param {QUANTITY} id - The filter id. Ex: "0x7"
 * @callback callback
 * @param {error} err - Error Object
 * @param {Boolean} result - true if the filter was successfully uninstalled, otherwise false.
 */
GvapApiDouble.prototype.shh_uninstallFilter = function(id, callback) {
  callback(null, false);
};

/**
 * Polling method for whisper filters. Returns new messages since the last call of this method.
 *
 * @param {QUANTITY} id - The filter id. Ex: "0x7"
 * @callback callback
 * @param {error} err - Error Object
 * @param {Array} result - More Info: https://github.com/vaporyco/wiki/wiki/JSON-RPC#shh_getfilterchanges
 */
GvapApiDouble.prototype.shh_getFilterChanges = function(id, callback) {
  callback(null, []);
};

/**
 * Get all messages matching a filter. Unlike shh_getFilterChanges this returns all messages.
 *
 * @param {QUANTITY} id - The filter id. Ex: "0x7"
 * @callback callback
 * @param {error} err - Error Object
 * @param {Array} result - See: shh_getFilterChanges
 */
GvapApiDouble.prototype.shh_getMessages = function(id, callback) {
  callback(null, false);
};

module.exports = GvapApiDouble;
