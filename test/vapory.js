var Web3 = require('@vapory/web3');
var assert = require('assert');
var Ganache = require("../index.js");


describe("Vapory", function(done) {
  var web3 = new Web3();
  var provider;

  before("Initialize the provider", function() {
    provider = Ganache.provider();
    web3.setProvider(provider);
  });

  it("should get vapory version (vap_protocolVersion)", function() {
    return web3.vap.getProtocolVersion().then(result => {
      assert.equal(result, "63", "Network Version should be 63");
    })
  });
});
