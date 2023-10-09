import {
  Address,
  beginCell,
  Cell,
  Contract,
  contractAddress,
  ContractProvider, Dictionary, DictionaryValue,
  Sender,
  SendMode, toNano
} from 'ton-core';
import {TupleItemSlice} from "ton-core/dist/tuple/tuple";

export type IDOConfig = {
  owner: Address;
  referrals: { address: Address, referralID: string, batch:string }[];
  TONNEL_MASTER: Address;
};

const CellRef: DictionaryValue<Cell> = {
  serialize: (src, builder) => {
    builder.storeSlice(src.beginParse())
  },
  parse: (src) => src.asCell(),
}

function getCashBack(batch: string) {
  if (batch === "gold") {
    return 40;
  }
  if (batch === "silver") {
    return 25;
  }
  if (batch === "bronze") {
    return 15;

  }
  if (batch === "inactiveBronze") {
    return 10;
  }
  return 0
}

function getReferral(batch: string) {
 if (batch === "gold") {
   return 70;
 }
    if (batch === "silver") {
        return 50;
    }
    if (batch === "bronze") {
        return 30;

    }
    if (batch === "inactiveBronze") {
        return 20;
    }
    return 10
}

export function IDOConfigToCell(config: IDOConfig): Cell {
  const empty = Dictionary.empty(Dictionary.Keys.BigUint(256), CellRef)
  config.referrals.forEach((item) => {
    empty.set(
      BigInt("0x" + beginCell().storeStringTail(item.referralID).endCell().hash().toString('hex')),
      beginCell().storeUint(getCashBack(item.batch),8).storeUint(getReferral(item.batch),8).storeAddress(item.address).endCell()
    )
  })
  const unixTime = Math.floor(new Date().getTime() / 1000);

  return beginCell().storeDict(empty).storeDict(null).storeAddress(config.owner).storeBit(1).storeCoins(0).storeCoins(toNano('1')).storeCoins(0).storeUint(unixTime,32).storeAddress(config.TONNEL_MASTER).endCell()
}

export const Opcodes = {
  buy_TONNEL: 846073365,
  withdraw_TON: 3280699740,
  finish_sale: 1641017685,
  start_sale: 3164944080,
  claim_TONNEL: 4060617894,
};
export const ERRORS = {
  not_staked: 700,
  not_enough: 701

};

export class IDO implements Contract {
  constructor(readonly address: Address, readonly init?: { code: Cell; data: Cell }) {
  }

  static createFromAddress(address: Address) {
    return new IDO(address);
  }

  static createFromConfig(config: IDOConfig, code: Cell, workchain = 0) {
    const data = IDOConfigToCell(config);
    const init = {code, data};
    return new IDO(contractAddress(workchain, init), init);
  }

  async sendDeploy(provider: ContractProvider, via: Sender, value: bigint) {
    await provider.internal(via, {
      value,
      sendMode: SendMode.PAY_GAS_SEPARATELY,
      body: beginCell().endCell(),
    });
  }

  async sendBuyTONNEL(provider: ContractProvider, via: Sender, value: bigint, referralID: string) {
    await provider.internal(via, {
      value,
      sendMode: SendMode.PAY_GAS_SEPARATELY,
      body: beginCell().storeUint(Opcodes.buy_TONNEL, 32).storeUint(0, 64).storeUint(BigInt("0x" + beginCell().storeStringTail(referralID).endCell().hash().toString('hex')), 256).endCell(),
    });
  }

  async sendWithdrawTON(provider: ContractProvider, via: Sender, value: bigint, amount: bigint) {
    await provider.internal(via, {
      value,
      sendMode: SendMode.PAY_GAS_SEPARATELY,
      body: beginCell().storeUint(Opcodes.withdraw_TON, 32).storeUint(0, 64).storeCoins(amount).endCell(),
    });
  }

  async sendClaimTONNEL(provider: ContractProvider, via: Sender, value: bigint) {
    await provider.internal(via, {
      value,
      sendMode: SendMode.PAY_GAS_SEPARATELY,
      body: beginCell().storeUint(Opcodes.claim_TONNEL, 32).storeUint(0, 64).endCell(),
    });
  }

  async sendFinishSale(provider: ContractProvider, via: Sender, value: bigint) {
    await provider.internal(via, {
      value,
      sendMode: SendMode.PAY_GAS_SEPARATELY,
      body: beginCell().storeUint(Opcodes.finish_sale, 32).storeUint(0, 64).endCell(),
    });
  }
  async sendStartSale(provider: ContractProvider, via: Sender, value: bigint) {
    await provider.internal(via, {
      value,
      sendMode: SendMode.PAY_GAS_SEPARATELY,
      body: beginCell().storeUint(Opcodes.start_sale, 32).storeUint(0, 64).endCell(),
    });
  }



  async getBalance(provider: ContractProvider) {
    const result = await provider.getState();
    return result.balance;
  }

  async getState(provider: ContractProvider) {
    const result = await provider.get('get_state', []);
    return result.stack;
  }

  async getPrice(provider: ContractProvider) {
    const result = await provider.get('get_price', []);
    console.log(result.stack)
    return result.stack.readBigNumber();
  }

  async getReferral(provider: ContractProvider, referrerId:string) {
    const result = await provider.get('get_referral', [
      {type: 'int', value: BigInt("0x" + beginCell().storeStringTail(referrerId).endCell().hash().toString('hex'))},
    ]);
    console.log(result.stack)
    return result.stack.readBigNumber();
  }

  async getTONNELPurchased(provider: ContractProvider, sender:Address) {
    const result = await provider.get('get_purchased', [
      {type: 'slice',
        cell: beginCell().storeAddress(sender).endCell()
      },
    ]);
    console.log(result.stack)
    return result.stack.readBigNumber();
  }

}
