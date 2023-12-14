import {Blockchain, SandboxContract, TreasuryContract} from '@ton-community/sandbox';
import {Address, beginCell, Cell, toNano} from 'ton-core';
import {ERRORS, Tonnel} from '../wrappers/Tonnel';
import '@ton-community/test-utils';
import {compile} from '@ton-community/blueprint';
import {MerkleTree, Sha256} from "../utils/merkleTree";
import {genProofArgs, rbuffer, toBigIntLE} from "../utils/circuit";
import path from "path";
// @ts-ignore
import { groth16 } from "snarkjs";
import {JettonMinter} from "../wrappers/JettonMinter";
import {JettonWallet} from "../wrappers/JettonWallet";
import exp = require("constants");

import * as testData from './test_data';
import {buildBls12381, utils} from "ffjavascript";
const {unstringifyBigInts} = utils;

const wasmPath = path.join(__dirname, "../build/circuits/circuit.wasm");
const zkeyPath = path.join(__dirname, "../build/circuits/circuit_final.zkey");

const fee = 0.02;
const pool_size = 5;
const deposit_fee = 0.95;
const withdraw_fee = 0.15;

export function parseG1Func(G1: bigint[]) {
  let num = G1[0]
  let y = BigInt(G1[1])
  y *= 2n;
  y /= 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787n;
  // padding to 381 bits
  let flag = y.toString(2)
  let cell = beginCell()
  num = BigInt(num)
  const bin  = num.toString(2)
  // padding to 384 bits
  const padding =  "10" + flag + bin.padStart(381, '0')
  // print each 48 bits
  for (let i = 0; i < padding.length; i += 48) {
    const chunk = padding.slice(i, i + 48)
    const dec = BigInt('0b' + chunk)
    // code += `.store_uint(${dec.toString(10)}, 48)`
    cell.storeUint(dec, 48)
  }

  return cell.endCell()

}
export function parseG2Func(num0: any, num1: any, ys:any) {
  let cell = beginCell()
  // a_flag1 = (y_im * 2) // q if y_im > 0 else (y_re * 2) // q python code
  let flag0
  if(ys[1] > 0) {
    ys[1] *= 2n;
    ys[1] /= 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787n;
    flag0 = ys[1].toString(2)
  } else {
    ys[0] *= 2n;
    ys[0] /= 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787n;
    flag0 = ys[0].toString(2)
  }
  // console.log(flag0)

  num1 = BigInt(num1)
  // console.log(num.toString(10))
  let bin  = num1.toString(2)
// padding to 384 bits
  let padding =  "10" + flag0 + bin.padStart(381, '0')
  for (let i = 0; i < padding.length; i += 96) {
    const chunk = padding.slice(i, i + 96)

    const dec = BigInt('0b' + chunk)
    // console.log(dec)
    cell.storeUint(dec, 96)
  }
  bin  = num0.toString(2)
// padding to 384 bits
  padding =  "000" + bin.padStart(381, '0')
  for (let i = 0; i < padding.length; i += 96) {
    const chunk = padding.slice(i, i + 96)
    const dec = BigInt('0b' + chunk)
    // console.log(dec)
    cell.storeUint(dec, 96)
  }
  return cell.endCell()

}
describe('Tonnel', () => {
  let code: Cell;
  let codeMaster: Cell;
  let codeWallet: Cell;
  beforeAll(async () => {
    code = await compile('Tonnel');
    codeMaster = await compile('JettonMinter');
    codeWallet = await compile('JettonWallet');


  });

  let blockchain: Blockchain;
  let tonnel: SandboxContract<Tonnel>;
  let tonnelJettonMaster: SandboxContract<JettonMinter>;
  let owner: SandboxContract<TreasuryContract>;
  beforeEach(async () => {
    blockchain = await Blockchain.create();
    owner = await blockchain.treasury('owner');
    tonnelJettonMaster = blockchain.openContract(JettonMinter.createFromConfig({
      adminAddress: owner.address,
      content: "https://api.tonnel.network/jetton/metadata",
      jettonWalletCode: codeWallet
    }, codeMaster));

    const deployer = await blockchain.treasury('deployer');
    const deployJettonResult = await tonnelJettonMaster.sendDeploy(owner.getSender(), toNano('0.05'));
    expect(deployJettonResult.transactions).toHaveTransaction({
      from: owner.address,
      to: tonnelJettonMaster.address,
      deploy: true,
      success: true,
    });

    tonnel = blockchain.openContract(
      Tonnel.createFromConfig(
        {
          ownerAddress: owner.address,
          tonnelJettonAddress: tonnelJettonMaster.address,
          depositorTonnelMint: 100,
          relayerTonnelMint: 50,

        },
        code
      )
    );


    const deployResult = await tonnel.sendDeploy(deployer.getSender(), toNano('0.05'));
    await tonnelJettonMaster.sendMintAccess(owner.getSender(),{
      value: toNano('0.02'),
      queryId: 0,
      mintAccess: tonnel.address
    })
    expect(deployResult.transactions).toHaveTransaction({
      from: deployer.address,
      to: tonnel.address,
      deploy: true,
      success: true,
    });
  });

  async function merkleInitialize() {
    const initSlice = 2;
    for (let i = 0; i < initSlice; i++) {
      console.log(`init ${i + 1}/${initSlice}`);

      const init_account = await blockchain.treasury('increaser' + i);


      const increaseResult = await tonnel.sendContinue(init_account.getSender(), {
        value: toNano('0.8'),
      });

      expect(increaseResult.transactions).toHaveTransaction({
        from: init_account.address,
        to: tonnel.address,
        success: true,
      });


    }
  }

  it('should init Merkle ', async () => {

    await merkleInitialize();

  });


  it('should init Merkle and then deposit', async () => {
    console.log('before-1', await tonnel.getBalance() / 1000000000n);

    await merkleInitialize();
    const tree = new MerkleTree(20);
    const rootInit = await tonnel.getLastRoot();
    expect(BigInt(tree.root())).toEqual(rootInit);
    console.log('before', Number(await tonnel.getBalance()) / 1000000000);

    const sender = await blockchain.treasury('sender');


    const randomBuf = rbuffer(31);
    const randomBuf2 = rbuffer(31);
    const nullifier = toBigIntLE(randomBuf2);
    const secret = toBigIntLE(randomBuf);
    const commitment = Sha256(secret.toString(), nullifier.toString());


    const depositResult = await tonnel.sendDeposit(sender.getSender(), {
      value: toNano((deposit_fee + pool_size * (1 + fee)).toString()),
      commitment: BigInt(commitment),

    });


    console.log('before1', Number(await tonnel.getBalance()) / 1000000000);

    expect(depositResult.transactions).toHaveTransaction({
      from: sender.address,
      to: tonnel.address,
      success: true,
    });

    expect(depositResult.transactions).toHaveTransaction({
      from: tonnel.address,
      to: owner.address,
      success: true,
      value: toNano((pool_size * fee).toString()),
    });

    expect(depositResult.transactions).toHaveTransaction({
      from: tonnel.address,
      to: tonnelJettonMaster.address,
      success: true,
    })
    const jettonWalletDepositorContract = await blockchain.openContract(
      JettonWallet.createFromAddress(await tonnelJettonMaster.getWalletAddress(sender.address)))
    expect(depositResult.transactions).toHaveTransaction({
      from: tonnelJettonMaster.address,
      to: jettonWalletDepositorContract.address,
      success: true,
    })



    expect(await jettonWalletDepositorContract.getBalance()).toEqual(toNano(100))

    expect(await tonnel.getBalance()).toBeGreaterThan(toNano(pool_size))
    tree.insert(commitment);

    const increaseResult2 = await tonnel.sendContinue(sender.getSender(), {
      value: toNano('0.8'),
    });

    expect(increaseResult2.transactions).toHaveTransaction({
      from: sender.address,
      to: tonnel.address,
      success: true,
    });
    const rootAfter = await tonnel.getLastRoot();
    expect(BigInt(tree.root())).toEqual(rootAfter);
    console.log('after', Number(await tonnel.getBalance()) / 1000000000);


  });

  it('should init Merkle and then revert on invalid deposit', async () => {
    await merkleInitialize();
    const tree = new MerkleTree(20);
    const rootInit = await tonnel.getLastRoot();
    expect(BigInt(tree.root())).toEqual(rootInit);
    console.log('before', Number(await tonnel.getBalance()) / 1000000000);


    const sender = await blockchain.treasury('sender');


    const randomBuf = rbuffer(31);
    const randomBuf2 = rbuffer(31);
    const nullifier = toBigIntLE(randomBuf2);
    const secret = toBigIntLE(randomBuf);
    const commitment = Sha256(secret.toString(), nullifier.toString());


    const depoistResult = await tonnel.sendDeposit(sender.getSender(), {
      value: toNano((deposit_fee).toString()), // not enough fund error
      commitment: BigInt(commitment),

    });

    expect(depoistResult.transactions).toHaveTransaction({
      from: sender.address,
      to: tonnel.address,
      success: false,
      exitCode: ERRORS.fund
    });

    console.log('after', Number(await tonnel.getBalance()) / 1000000000);


  });

  function reformatVerificationKeyGroth16(curve, verificationKey) {
    const vk_verifier = unstringifyBigInts(verificationKey);

    verificationKey.vk_alpha_1 = g1Compressed(curve, vk_verifier.vk_alpha_1);
    verificationKey.vk_alpha_1_array = g1Compressed_to_array(curve, vk_verifier.vk_alpha_1);
    verificationKey.vk_beta_2 = g2Compressed(curve, vk_verifier.vk_beta_2);
    verificationKey.vk_beta_2_array = g2Compressed_to_array(curve, vk_verifier.vk_beta_2);
    verificationKey.vk_gamma_2 = g2Compressed(curve, vk_verifier.vk_gamma_2);
    verificationKey.vk_gamma_2_array = g2Compressed_to_array(curve, vk_verifier.vk_gamma_2);
    verificationKey.vk_delta_2 = g2Compressed(curve, vk_verifier.vk_delta_2);
    verificationKey.vk_delta_2_array = g2Compressed_to_array(curve, vk_verifier.vk_delta_2);
    let arr = vk_verifier.IC.map(x => g1Compressed(curve, x));
    verificationKey.IC = arr;
    verificationKey.IC_array = vk_verifier.IC.map(x => g1Compressed_to_array(curve, x));
    return verificationKey;
  }
  function g1Compressed(curve, p1Raw) {
      let p1 = curve.G1.fromObject(p1Raw);
  
      let buff = new Uint8Array(48);
      curve.G1.toRprCompressed(buff, 0, p1);
      // console.log(" > p1Raw = ", p1Raw)
      // console.log(" > p1 = ", p1)
      // console.log(" > buff = ", buff)
      // convert from ffjavascript to blst format
      if (buff[0] & 0x80) {
          buff[0] |= 32;
      }
      buff[0] |= 0x80;
      // console.log(" > buff* = ", buff)
      return toHexString(buff);
  }
  function g1Compressed_to_array(curve, p1Raw) {
    let p1 = curve.G1.fromObject(p1Raw);

    let buff = new Uint8Array(48);
    curve.G1.toRprCompressed(buff, 0, p1);
    // console.log(" > p1Raw = ", p1Raw)
    // console.log(" > p1 = ", p1)
    // console.log(" > buff = ", buff)
    // convert from ffjavascript to blst format
    if (buff[0] & 0x80) {
        buff[0] |= 32;
    }
    buff[0] |= 0x80;
    // console.log(" > buff* = ", buff)
    return toBigIntArray(buff, 8); //split as 8 slices
  }
    
  function g2Compressed(curve, p2Raw) {
      let p2 = curve.G2.fromObject(p2Raw);
  
      let buff = new Uint8Array(96);
      curve.G2.toRprCompressed(buff, 0, p2);
      // convert from ffjavascript to blst format
      if (buff[0] & 0x80) {
          buff[0] |= 32;
      }
      buff[0] |= 0x80;
      return toHexString(buff);
  }

  function g2Compressed_to_array(curve, p2Raw) {
    let p2 = curve.G2.fromObject(p2Raw);

    let buff = new Uint8Array(96);
    curve.G2.toRprCompressed(buff, 0, p2);
    // convert from ffjavascript to blst format
    if (buff[0] & 0x80) {
        buff[0] |= 32;
    }
    buff[0] |= 0x80;
    return toBigIntArray(buff, 8); //split as 8 slices
  }
    
  function toHexString(byteArray) {
      return Array.from(byteArray, function (byte: any) {
          return ('0' + (byte & 0xFF).toString(16)).slice(-2);
      }).join("");
  }
  function toBigIntArray(byteArray, nSlices) {
    var len = byteArray.length;
    expect(len % nSlices).toEqual(0);
    var chunkSize = len / nSlices;
    var results = [''];
    for (let i =0; i < len; i += chunkSize) {
      const chunk = byteArray.slice(i, i + chunkSize);
      const dec = BigInt('0x' + toHexString(chunk));
      console.log('ZYD:', dec.toString());
      results.push(dec.toString());
    }
    return results;
  }

  it('should init Merkle and then deposit and then withdraw', async () => {
    await merkleInitialize();
    const tree = new MerkleTree(20);
    const rootInit = await tonnel.getLastRoot();
    expect(BigInt(tree.root())).toEqual(rootInit);
    console.log('before', await tonnel.getBalance());

    const sender = await blockchain.treasury('sender');
    const cell_address_sender = beginCell().storeAddress(sender.address).endCell();
    const cell_address_owner = beginCell().storeAddress(owner.address).endCell();


    const randomBuf = rbuffer(31);
    const randomBuf2 = rbuffer(31);
    const nullifier = toBigIntLE(randomBuf2);
    const secret = toBigIntLE(randomBuf);
    const commitment = Sha256(secret.toString(), nullifier.toString());


    const increaseResult = await tonnel.sendDeposit(sender.getSender(), {
      value: toNano((deposit_fee + pool_size * (1 + fee)).toString()),
      commitment: BigInt(commitment),

    });

    expect(increaseResult.transactions).toHaveTransaction({
      from: sender.address,
      to: tonnel.address,
      success: true,
    });

    expect(increaseResult.transactions).toHaveTransaction({
      from: tonnel.address,
      to: owner.address,
      success: true,
      value: toNano((pool_size * fee).toString()),
    });


    expect(increaseResult.transactions).toHaveTransaction({
      from: tonnel.address,
      to: tonnelJettonMaster.address,
      success: true,
    })
    const jettonWalletDepositorContract = await blockchain.openContract(
      JettonWallet.createFromAddress(await tonnelJettonMaster.getWalletAddress(sender.address)))
    expect(increaseResult.transactions).toHaveTransaction({
      from: tonnelJettonMaster.address,
      to: jettonWalletDepositorContract.address,
      success: true,
    })
    expect(await jettonWalletDepositorContract.getBalance()).toEqual(toNano(100))


    expect(await tonnel.getBalance()).toBeGreaterThan(toNano(pool_size))
    tree.insert(commitment);

    const increaseResult2 = await tonnel.sendContinue(sender.getSender(), {
      value: toNano('0.8'),
    });
    expect(increaseResult2.transactions).toHaveTransaction({
      from: sender.address,
      to: tonnel.address,
      success: true,
    });



    ///second deposit


    for (let i = 0; i < 120; i++) {
      const randomBuf_2 = rbuffer(31);
      const randomBuf2_2 = rbuffer(31);
      const nullifier_2 = toBigIntLE(randomBuf2_2);
      const secret_2 = toBigIntLE(randomBuf_2);
      const commitment_2 = Sha256(secret_2.toString(), nullifier_2.toString());
      await tonnel.sendDeposit(sender.getSender(), {
        value: toNano((deposit_fee + pool_size * (1 + fee)).toString()),
        commitment: BigInt(commitment_2),

      });
      tree.insert(commitment_2);

      await tonnel.sendContinue(sender.getSender(), {
        value: toNano('0.8'),
      });
    }
    ///second deposit end

    const merkleProof = tree.proof(0);

    const rootAfter = await tonnel.getLastRoot();
    expect(BigInt(tree.root())).toEqual(rootAfter);


    const input = {
      root: tree.root(),
      secret: secret.toString(),
      nullifier: nullifier.toString(),
      nullifierHash: Sha256(nullifier.toString(), nullifier.toString()),
      fee: 10,
      recipient: cell_address_sender.beginParse().loadUintBig(256),
      pathElements: merkleProof.pathElements,
      pathIndices: merkleProof.pathIndices,
    };

    // get the eliptic curve first
    let curve = await buildBls12381();

    let verification_key = testData.verification_key;
    console.log('verification_key = ', verification_key);
    let verifier_key = reformatVerificationKeyGroth16(curve, verification_key);
    console.log('verifier_key = ', verifier_key);


    let {proof, publicSignals} = await groth16.fullProve(input, wasmPath, zkeyPath);

    const B_x = proof.pi_b[0].map((num: string) => BigInt(num))
    const B_y  = proof.pi_b[1].map((num: string) => BigInt(num))
    const known = await tonnel.getRootKnown(BigInt(input.root));
    expect(known).toEqual(1);


    const withdrawResult = await tonnel.sendWithdraw(owner.getSender(), {
      value: toNano((withdraw_fee).toString()),
      root: BigInt(publicSignals[0]),
      nullifierHash: BigInt(publicSignals[1]),
      recipient: sender.address,
      fee: BigInt(publicSignals[3]),
      a: parseG1Func(proof.pi_a.slice(0,2).map((num: string ) => BigInt(num))),
      b: parseG2Func(B_x[0], B_x[1], B_y),
      c: parseG1Func(proof.pi_c.slice(0,2).map((num: string ) => BigInt(num))),
    });

    expect(withdrawResult.transactions).toHaveTransaction({
      from: owner.address,
      to: tonnel.address,
      success: true,
    });
    expect(withdrawResult.transactions).toHaveTransaction({
      from: tonnel.address,
      to: owner.address,
      success: true,
      value: toNano((pool_size * 10 / 1000).toString()),
    });
    expect(withdrawResult.transactions).toHaveTransaction({
      from: tonnel.address,
      to: sender.address,
      success: true,
      value: toNano((pool_size * (1000 - 10) / 1000).toString()),
    });
    expect(withdrawResult.transactions).toHaveTransaction({
      from: tonnel.address,
      to: tonnelJettonMaster.address,
      success: true,
    })
    const jettonWalletRelayerContract = await blockchain.openContract(
      JettonWallet.createFromAddress(await tonnelJettonMaster.getWalletAddress(owner.address)))
    expect(withdrawResult.transactions).toHaveTransaction({
      from: tonnelJettonMaster.address,
      to: jettonWalletRelayerContract.address,
      success: true,
    })
    expect(await jettonWalletRelayerContract.getBalance()).toEqual(toNano(50))


    console.log('after', await tonnel.getBalance());


  }, 500000);


  // it('should init Merkle and then deposit and then some invalid txs(With pre-generated proofs and inputs)', async () => {
  //   await merkleInitialize();
  //   const tree = new MerkleTree(20);
  //   const rootInit = await tonnel.getLastRoot();
  //   expect(BigInt(tree.root())).toEqual(rootInit);
  //
  //   const sender = await blockchain.treasury('sender');
  //   const cell_address_sender = beginCell().storeAddress(sender.address).endCell();
  //   const cell_address_owner = beginCell().storeAddress(owner.address).endCell();
  //
  //
  //   const randomBuf = rbuffer(31);
  //   const randomBuf2 = rbuffer(31);
  //   // const nullifier = toBigIntLE(randomBuf2);
  //   // const secret = toBigIntLE(randomBuf);
  //   const nullifier = "284741391258851987273066117465250401658211913176434555769699128238924427012"
  //   let secret = "294170850052247494318845152993032133433606306560827844618331541287033881968"
  //   console.log('secret', secret.toString())
  //   console.log('nullifier', nullifier.toString())
  //   const commitment = Sha256(secret.toString(), nullifier.toString());
  //
  //
  //   const increaseResult = await tonnel.sendDeposit(sender.getSender(), {
  //     value: toNano((deposit_fee + pool_size * (1 + fee)).toString()),
  //     commitment: BigInt(commitment),
  //
  //   });
  //
  //   expect(increaseResult.transactions).toHaveTransaction({
  //     from: sender.address,
  //     to: tonnel.address,
  //     success: true,
  //   });
  //
  //   expect(increaseResult.transactions).toHaveTransaction({
  //     from: tonnel.address,
  //     to: owner.address,
  //     success: true,
  //     value: toNano((pool_size * fee).toString()),
  //   });
  //   expect(await tonnel.getBalance()).toBeGreaterThan(toNano(pool_size))
  //   tree.insert(commitment);
  //   const merkleProof = tree.proof(0);
  //
  //   const increaseResult2 = await tonnel.sendContinue(sender.getSender(), {
  //     value: toNano('0.8'),
  //   });
  //   expect(increaseResult2.transactions).toHaveTransaction({
  //     from: sender.address,
  //     to: tonnel.address,
  //     success: true,
  //   });
  //   const rootAfter = await tonnel.getLastRoot();
  //   expect(BigInt(tree.root())).toEqual(rootAfter);
  //
  //
  //   // const input = {
  //   //   root: tree.root(),
  //   //   secret: secret.toString(),
  //   //   nullifier: nullifier.toString(),
  //   //   nullifierHash: Sha256(nullifier.toString(), nullifier.toString()),
  //   //   fee: 10,
  //   //   recipient: cell_address_sender.beginParse().loadUintBig(256),
  //   //   relayer: cell_address_owner.beginParse().loadUintBig(256),
  //   //
  //   //   pathElements: merkleProof.pathElements,
  //   //   pathIndices: merkleProof.pathIndices,
  //   // };
  //
  //
  //   // let {proof, publicSignals} = await groth16.fullProve(input, wasmPath, zkeyPath);
  //   // console.log('publicSignals', publicSignals)
  //   // console.log('proof', proof)
  //   let proof =  {
  //     pi_a: [
  //       '3913154814462420064178596594583685198711621933712374661025907427076958133973715943592548689611851589624637647485533',
  //       '1949826439636536999114193859292313943118507621594074238865663437438314408133687958124611763975678875535137703923355',
  //       '1'
  //     ],
  //     pi_b: [
  //       [
  //         '108817148224187241299480705372205651555417174168131983503515375010672506573162731686239923103349164102922202486188',
  //         '105449591120517016663997384078720570416409913046980740938659767112434720761148110458776710450199824136753013825984'
  //       ],
  //       [
  //         '2238842924159216323413953126780358828608855527254936394252225254292900675190327172379177348070196807511497481959519',
  //         '1157833459710116065703813841501227812921849216841052504092003947011433632047712588079028154985521076222600307664691'
  //       ],
  //       [ '1', '0' ]
  //     ],
  //     pi_c: [
  //       '3601962559803233164389938885867217131473116888368336257535939938717426698653468656869068756750669233573099531573859',
  //       '3289999151513477234098718438539946743899086989791381527936042905753633927695897110057200750487163860915936366627189',
  //       '1'
  //     ],
  //     protocol: 'groth16',
  //     curve: 'bls12381'
  //   }
  //   let publicSignals =  [
  //     '10934624895302180659671845926392135083241805773152440108976930874739508653527',
  //     '48759474743477377679240327706664862083466080881053914687695063497158044362968',
  //     '5477617119893546710537552393898901286136209382584656943527614528969593445475',
  //     '5475112502061704042564098634582499353301677279502282160480018399738705888834',
  //     '10'
  //   ]
  //
  //   const B_x = proof.pi_b[0].map((num: string) => BigInt(num))
  //   const B_y  = proof.pi_b[1].map((num: string) => BigInt(num))
  //
  //   const withdrawResult = await tonnel.sendWithdraw(sender.getSender(), {
  //     value: toNano((deposit_fee + pool_size * (1 + fee)).toString()),
  //     root: BigInt(publicSignals[0]),
  //     nullifierHash: BigInt(publicSignals[1]),
  //     recipient: sender.address,
  //     fee: BigInt(publicSignals[4]),
  //     relayer: owner.address,
  //     a: parseG1Func(proof.pi_a.slice(0,2).map((num: string ) => BigInt(num))),
  //     b: parseG2Func(B_x[0], B_x[1], B_y),
  //     c: parseG1Func(proof.pi_c.slice(0,2).map((num: string ) => BigInt(num))),
  //   });
  //
  //   expect(withdrawResult.transactions).toHaveTransaction({
  //     from: sender.address,
  //     to: tonnel.address,
  //     success: true,
  //   });
  //   expect(withdrawResult.transactions).toHaveTransaction({
  //     from: tonnel.address,
  //     to: owner.address,
  //     success: true,
  //     value: toNano((pool_size * 10 / 1000).toString()),
  //   });
  //   expect(withdrawResult.transactions).toHaveTransaction({
  //     from: tonnel.address,
  //     to: sender.address,
  //     success: true,
  //     value: toNano((pool_size * (1000 - 10) / 1000).toString()),
  //   });
  //   const withdrawResult2 = await tonnel.sendWithdraw(sender.getSender(), {
  //     value: toNano((deposit_fee + pool_size * (1 + fee)).toString()),
  //     root: BigInt(publicSignals[0]),
  //     nullifierHash: BigInt(publicSignals[1]),
  //     recipient: sender.address,
  //     fee: BigInt(publicSignals[4]),
  //     relayer: owner.address,
  //     a: parseG1Func(proof.pi_a.slice(0,2).map((num: string ) => BigInt(num))),
  //     b: parseG2Func(B_x[0], B_x[1], B_y),
  //     c: parseG1Func(proof.pi_c.slice(0,2).map((num: string ) => BigInt(num))),
  //   });
  //
  //   expect(withdrawResult2.transactions).toHaveTransaction({
  //     from: sender.address,
  //     to: tonnel.address,
  //     exitCode: ERRORS.verify_failed_double_spend,
  //   });
  //
  //   const withdrawResult3 = await tonnel.sendWithdraw(sender.getSender(), {
  //     value: toNano((deposit_fee + pool_size * (1 + fee)).toString()),
  //     root: BigInt("123123123"),
  //     nullifierHash: BigInt(publicSignals[1]),
  //     recipient: sender.address,
  //     fee: BigInt(publicSignals[4]),
  //     relayer: owner.address,
  //     a: parseG1Func(proof.pi_a.slice(0,2).map((num: string ) => BigInt(num))),
  //     b: parseG2Func(B_x[0], B_x[1], B_y),
  //     c: parseG1Func(proof.pi_c.slice(0,2).map((num: string ) => BigInt(num))),
  //   });
  //
  //   expect(withdrawResult3.transactions).toHaveTransaction({
  //     from: sender.address,
  //     to: tonnel.address,
  //     exitCode: ERRORS.verify_failed_root,
  //   });
  //
  //   const withdrawResult4 = await tonnel.sendWithdraw(sender.getSender(), {
  //     value: toNano((deposit_fee + pool_size * (1 + fee)).toString()),
  //     root: BigInt("123123123"),
  //     nullifierHash: BigInt(publicSignals[1]),
  //     recipient: sender.address,
  //     fee: BigInt(1001),
  //     relayer: owner.address,
  //     a: parseG1Func(proof.pi_a.slice(0,2).map((num: string ) => BigInt(num))),
  //     b: parseG2Func(B_x[0], B_x[1], B_y),
  //     c: parseG1Func(proof.pi_c.slice(0,2).map((num: string ) => BigInt(num))),
  //   });
  //
  //   expect(withdrawResult4.transactions).toHaveTransaction({
  //     from: sender.address,
  //     to: tonnel.address,
  //     exitCode: ERRORS.verify_failed_fee,
  //   });
  //
  //
  //
  //
  // }, 500000);

});
