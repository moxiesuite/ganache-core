var Web3 = require("web3");
var assert = require("assert");
var Ganache = require(process.env.TEST_BUILD
  ? "../build/ganache.core." + process.env.TEST_BUILD + ".js"
  : "../index.js");

describe("Vapory", function(done) {
  var web3 = new Web3();
  var provider;

  before("Initialize the provider", function() {
    provider = Ganache.provider();
    web3.setProvider(provider);
  });

  it("should get vapory version (vap_protocolVersion)", function() {
    return web3.vap.getProtocolVersion().then((result) => {
      assert.strictEqual(result, "63", "Network Version should be 63");
    });
  });
});
