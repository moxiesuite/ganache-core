[![npm](https://img.shields.io/npm/v/ganache-core.svg)]()
[![npm](https://img.shields.io/npm/dm/ganache-core.svg)]()
[![Build Status](https://travis-ci.org/moxiesuite/ganache-core.svg?branch=master)](https://travis-ci.org/moxiesuite/ganache-core)
# Ganache Core

This is the core code that powers the Ganache application and the the Ganache command line tool.

# INSTALL

`ganache-core` is written in Javascript and distributed as a Node package via `npm`. Make sure you have Node.js (>= v6.11.5) installed, and your environment is capable of installing and compiling `npm` modules.

**macOS** Make sure you have the XCode Command Line Tools installed. These are needed in general to be able to compile most C based languages on your machine, as well as many npm modules.

**Windows** See our [Windows install instructions](https://github.com/vaporyjs/testrpc/wiki/Installing-TestRPC-on-Windows).

**Ubuntu/Linux** Follow the basic instructions for installing [Node.js](https://nodejs.org/en/download/package-manager/#debian-and-ubuntu-based-linux-distributions) and make sure that you have `npm` installed, as well as the `build-essential` `apt` package (it supplies `make` which you will need to compile most things). Use the official Node.js packages, *do not use the package supplied by your distribution.*


```Bash
npm install ganache-core
```

# USAGE

As a Web3 provider:

```javascript
var Ganache = require("ganache-core");
web3.setProvider(Ganache.provider());
```

As a general http server:

```javascript
var Ganache = require("ganache-core");
var server = Ganache.server();
server.listen(port, function(err, blockchain) {...});
```

Both `.provider()` and `.server()` take a single object which allows you to specify behavior of the Ganache instance. This parameter is optional. Available options are:

* `"accounts"`: `Array` of `Object`'s. Each object should have a balance key with a hexadecimal value. The key `secretKey` can also be specified, which represents the account's private key. If no `secretKey`, the address is auto-generated with the given balance. If specified, the key is used to determine the account's address.
* `"debug"`: `boolean` - Output VM opcodes for debugging
* `"logger"`: `Object` - Object, like `console`, that implements a `log()` function.
* `"mnemonic"`: Use a specific HD wallet mnemonic to generate initial addresses.
* `"port"`: Port number to listen on when running as a server.
* `"seed"`: Use arbitrary data to generate the HD wallet mnemonic to be used.
* `"total_accounts"`: `number` - Number of accounts to generate at startup.
* `"fork"`: `string` or `object` - When a `string`, same as `--fork` option above. Can also be a Web3 Provider object, optionally used in conjunction with the `fork_block_number` option below.
* `"fork_block_number"`: `string` or `number` - Block number the provider should fork from, when the `fork` option is specified. If the `fork` option is specified as a string including the `@` sign and a block number, the block number in the `fork` parameter takes precedence.  
* `"network_id"`: `integer` - Same as `--networkId` option above.
* `"time"`: `Date` - Date that the first block should start. Use this feature, along with the `vvm_increaseTime` method to test time-dependent code.
* `"locked"`: `boolean` - whether or not accounts are locked by default.
* `"unlocked_accounts"`: `Array` - array of addresses or address indexes specifying which accounts should be unlocked.
* `"db_path"`: `String` - Specify a path to a directory to save the chain database. If a database already exists, that chain will be initialized instead of creating a new one.
* `"db"`: `Object` - Specify an alternative database instance, for instance [MemDOWN](https://github.com/level/memdown).

# IMPLEMENTED METHODS

The RPC methods currently implemented are:

* `bzz_hive` (stub)
* `bzz_info` (stub)
* `debug_traceTransaction`
* `vap_accounts`
* `vap_blockNumber`
* `vap_call`
* `vap_coinbase`
* `vap_estimateGas`
* `vap_gasPrice`
* `vap_getBalance`
* `vap_getBlockByNumber`
* `vap_getBlockByHash`
* `vap_getBlockTransactionCountByHash`
* `vap_getBlockTransactionCountByNumber`
* `vap_getCode` (only supports block number “latest”)
* `vap_getCompilers`
* `vap_getFilterChanges`
* `vap_getFilterLogs`
* `vap_getLogs`
* `vap_getStorageAt`
* `vap_getTransactionByHash`
* `vap_getTransactionByBlockHashAndIndex`
* `vap_getTransactionByBlockNumberAndIndex`
* `vap_getTransactionCount`
* `vap_getTransactionReceipt`
* `vap_hashrate`
* `vap_mining`
* `vap_newBlockFilter`
* `vap_newFilter` (includes log/event filters)
* `vap_protocolVersion`
* `vap_sendTransaction`
* `vap_sendRawTransaction`
* `vap_sign`
* `vap_syncing`
* `vap_uninstallFilter`
* `net_listening`
* `net_peerCount`
* `net_version`
* `miner_start`
* `miner_stop`
* `personal_listAccounts`
* `personal_lockAccount`
* `personal_newAccount`
* `personal_unlockAccount`
* `personal_sendTransaction`
* `shh_version`
* `rpc_modules`
* `web3_clientVersion`
* `web3_sha3`

There’s also special non-standard methods that aren’t included within the original RPC specification:

* `vvm_snapshot` : Snapshot the state of the blockchain at the current block. Takes no parameters. Returns the integer id of the snapshot created.
* `vvm_revert` : Revert the state of the blockchain to a previous snapshot. Takes a single parameter, which is the snapshot id to revert to. If no snapshot id is passed it will revert to the latest snapshot. Returns `true`.
* `vvm_increaseTime` : Jump forward in time. Takes one parameter, which is the amount of time to increase in seconds. Returns the total time adjustment, in seconds.
* `vvm_mine` : Force a block to be mined. Takes no parameters. Mines a block independent of whether or not mining is started or stopped.

# Unsupported Methods

* `vap_compileSolidity`: If you'd like Solidity compilation in Javascript, please see the [vapory solc-js project](https://github.com/vaporyco/solc-js).


# TESTING

Run tests via:

```
$ npm test
```

# LICENSE
[MIT](https://tldrlegal.com/license/mit-license)
