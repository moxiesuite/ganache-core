var BN = require("bn.js");
var Web3 = require("web3");
var assert = require("assert-match");
var matchers = require("assert-match/matchers");
var Ganache = require(process.env.TEST_BUILD
  ? "../build/ganache.core." + process.env.TEST_BUILD + ".js"
  : "../index.js");
var utils = require("vaporyjs-util");
var pify = require("pify");

var regex = matchers.regex;

describe("stability", function(done) {
  var web3 = new Web3();
  var provider;
  var accounts;

  before("Initialize the provider", function() {
    provider = Ganache.provider({});
    web3.setProvider(provider);
  });

  before(function(done) {
    web3.vap.getAccounts(function(err, accs) {
      if (err) {
        return done(err);
      }

      accounts = accs;
      done();
    });
  });

  it("should be able to handle multiple transactions at once and manage nonces accordingly", function(done) {
    var expected = 5;
    var received = 0;

    var txHandler = function(err, result) {
      received += 1;

      if (received > expected) {
        throw new Error("Callback called too many times");
      }

      if (err || received === expected) {
        return done(err);
      }
    };

    // Fire off transaction at once
    for (var i = 0; i < expected; i++) {
      web3.vap.sendTransaction(
        {
          from: accounts[0],
          to: accounts[1],
          value: web3.utils.toWei(new BN(1), "vapor")
        },
        txHandler
      );
    }
  });

  it("should be able to handle batch transactions", function(done) {
    var expected = 5;
    var request = [];

    for (var i = 0; i < expected; i++) {
      let req = web3.vap.sendTransaction.request({
        from: accounts[0],
        to: accounts[1],
        value: web3.utils.toWei(new BN(1), "vapor")
      });

      req.jsonrpc = "2.0";
      req.id = 100 + i;

      request.push(req);
    }

    provider.sendAsync(request, function(err, result) {
      assert.deepEqual(err, undefined);
      assert(Array.isArray(result));
      assert.deepEqual(result.length, expected);
      done();
    });
  });

  it("should not crash when receiving transactions which don't pass FakeTransaction validation", function(done) {
    provider.send(
      {
        jsonrpc: 2.0,
        id: 123,
        method: "vap_sendTransaction",
        params: [
          {
            from: accounts[0],
            to: "0x123", // bad address
            value: "1000000000000000000" // 1 VAP
          }
        ]
      },
      function(err, result) {
        assert.notEqual(err, undefined);
        assert.notEqual(result.error, undefined);
        done();
      }
    );
  });

  it("should not crash when receiving a request with too many arguments", function() {
    // At time of writing, `vvm_mine` takes 0 arguments
    return pify(provider.send)({
      jsonrpc: 2.0,
      id: 123,
      method: "vvm_mine",
      params: [
        "0x1",
        "0x2",
        "0x3",
        "0x4",
        "0x5",
        "0x6",
        "0x7",
        "0x8",
        "0x9",
        "0xA"
        // 10 oughtta do it!
      ]
    }).catch((err) => {
      assert.deepEqual(
        err.message,
        regex(
          /Incorrect number of arguments\. Method 'vvm_mine' requires between \d+ and \d+ arguments\. Request specified \d+ arguments: \[[^\]]*\]\./
        )
      );
    }); // nothing to check from here, if the promise rejects, test fails
  });

  // TODO: remove `.skip` when working on and/or submitting fix for issue #453
  describe.skip("race conditions", function(done) {
    var web3 = new Web3();
    var provider;
    var accounts;

    before("initialize the provider", function() {
      provider = Ganache.provider({});
      web3.setProvider(provider);
    });

    before("get accounts", function(done) {
      web3.vap.getAccounts(function(err, accs) {
        if (err) {
          return done(err);
        }

        accounts = accs;
        done();
      });
    });

    it("should not cause 'get' of undefined", function(done) {
      process.prependOnceListener("uncaughtException", function(err) {
        done(err);
      });

      var blockchain = provider.manager.state.blockchain;
      // processCall or processBlock
      blockchain.vm.stateManager.checkpoint();
      // getCode (or any function that calls trie.get)
      blockchain.stateTrie.get(utils.toBuffer(accounts[0]), function() {});
      blockchain.vm.stateManager.revert(function() {
        done();
      }); // processCall or processBlock
    });

    it("should not cause 'pop' of undefined", function(done) {
      process.prependOnceListener("uncaughtException", function(err) {
        done(err);
      });

      var blockchain = provider.manager.state.blockchain;
      blockchain.vm.stateManager.checkpoint(); // processCall #1
      // processNextBlock triggered by interval mining which at some point calls
      // vm.stateManager.commit() and blockchain.putBlock()
      blockchain.processNextBlock(function(err, tx, results) {
        if (err) {
          return done(err);
        }
        blockchain.vm.stateManager.revert(function() {
          // processCall #1 finishes
          blockchain.latestBlock(function(err, latestBlock) {
            if (err) {
              return done(err);
            }
            blockchain.stateTrie.root = latestBlock.header.stateRoot; // getCode #1 (or any function with this logic)
            web3.vap.call({}, function() {
              done();
            }); // processCall #2
          });
        });
      });
    });
  });
});
