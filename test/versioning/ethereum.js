const assert = require("assert");
const preloadWeb3 = require("../helpers/web3/preloadWeb3");

describe("Ethereum", () => {
  const services = preloadWeb3();

  it("should get ethereum version (eth_protocolVersion)", async() => {
    const { web3 } = services;

    const result = await web3.eth.getProtocolVersion();
    assert.strictEqual(result, "63", "Network Version should be 63");
  });
});