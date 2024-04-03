declare type Net = String;
declare type Shares = Array<String>;

interface wallet {
    hdKey: {
        HDpri: String,
        HDpub: String
    },
    keypair: {
        pri: String,
        pub: String
    },
    address: String
}

interface Signature {
    sig: {
        r: Number,
        s: Number
    }, 
    serialized_sig: String, 
    msgHash: ArrayBuffer, 
    recovery_id: Number
}

export declare class Custodial_Wallet {
    readonly net: Net;
    
    readonly hdKey: wallet["hdKey"];
    readonly keypair: wallet["keypair"];
    readonly address: wallet["address"];

    child_keys: Set<Object>;
    constructor(net: Net, wallet: wallet, serialization_format: Object);
    
    static fromRandom(net: Net, passphrase: String) : [String, Custodial_Wallet];
    static fromMnemonic(net: Net, mnemonic: String, passphrase: String) : Custodial_Wallet;
    static fromSeed(net: Net, seed: String) : Custodial_Wallet;
    
    derive(path: String, keyType: String) : Custodial_Wallet;
    sign(message: String) : [Uint8Array, Number];
    verify(sig: Uint8Array, message: String) : boolean;
}


export declare class Non_Custodial_Wallet {
    readonly net: Net;
    readonly group_size: Number;
    readonly threshold: Number;
    readonly publicKey: String;
    readonly _privateKey: String;
    readonly address: String;
    readonly _shares : Shares;

    constructor(net: Net, group_size: Number, threshold: Number);

    static fromRandom(net: Net, group_size: Number, threshold: Number) : Non_Custodial_Wallet;
    static fromShares(net: Net, shares: Shares, threshold: Number) : Non_Custodial_Wallet;

    sign(message: String) : Signature;
    verify(sig: Signature["sig"], msgHash: Signature["msgHash"]) : boolean;
}

export declare namespace CASH_ADDR {
    function to_cashAddr(legacy_address: string, type: string): string;
}

export declare namespace BECH32 {
    function to_P2WPKH(witness_program: string): string;
    function data_to_bech32(prefix: string, data: string, encoding: string): string;
}

export declare namespace schnorr_sig {
    function sign(private_key: string, msg: string): Uint8Array;
    function verify(sig: Uint8Array | ArrayBuffer, msg: string, public_key: Uint8Array | ArrayBuffer): boolean;
    function retrieve_public_key(private_key: Uint8Array | ArrayBuffer): Uint8Array;
}