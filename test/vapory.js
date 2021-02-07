var Web3 = require('@vapory/web3');
var assert = require('assert');
var TestRPC = require("../index.js");


describe("Vapory", function(done) {
  var web3 = new Web3();
  var provider;

  before("Initialize the provider", function() {
    provider = TestRPC.provider();
    web3.setProvider(provider);
  });

  it("should get vapory version (vap_protocolVersion)", function(done) {
    web3.version.getVapory(function(err, result){
      assert.equal(result, "63", "Network Version should be 63");
      done();
    })
  });
});
