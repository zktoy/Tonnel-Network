# ton-zk-verifier
This is the first zk verifier for TON blockchain.

## How to build
```bash
npm install
npm run build
```

## How to run test
```bash
npm run test
```

solidityParser.js is a parser for Verifier.sol code generated by snarkjs exportVerifer command. This parser will convert this solidity code to func contract that can easily be tested.


## Important notes
This is only working on testnet now. It is not working on mainnet until the next update of TON blockchain and BLS12-381 opcodes are added to the mainnet.