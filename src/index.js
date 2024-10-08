import crypto from "crypto";

import Transaction from "./Transaction.js";
import Blockchain from "./Blockchain.js";

(async () => {
    const user_01__keys = await crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const user_02__keys = await crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const user_03__keys = await crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const user_04__keys = await crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    
    const transaction_01__input_addr = "user_1";
    const transaction_01__output_addr = "user_2";
    const transaction_01__funds = 10;
    const transaction_01__timestamp = Date.now();
    const transaction_01__signature = crypto
        .createSign("SHA256") 
        .update(`${ transaction_01__input_addr }${ transaction_01__output_addr }${ transaction_01__funds }${ transaction_01__timestamp }`)
        .end() 
        .sign(
            user_01__keys
                .privateKey
                .export({ type: "pkcs1", format: "pem" }), 
            "hex"
        );

    const transaction_02__input_addr = "user_2";
    const transaction_02__output_addr = "user_3";
    const transaction_02__funds = 20;
    const transaction_02__timestamp = Date.now();
    const transaction_02__signature = crypto
        .createSign("SHA256")
        .update( 
            crypto.createHash("SHA256")
                .update(`${ transaction_02__input_addr }${ transaction_02__output_addr }${ transaction_02__funds }${ transaction_02__timestamp }`)
                .digest("hex")
        )
        .sign(user_02__keys.privateKey.export({ type: "pkcs1", format: "pem" }), "hex");
    
    const transaction_03__input_addr = "user_3";
    const transaction_03__output_addr = "user_4";
    const transaction_03__funds = 30;
    const transaction_03__timestamp = Date.now();
    const transaction_03__signature = crypto
        .createSign("SHA256")
        .update( 
            crypto.createHash("SHA256")
                .update(`${ transaction_03__input_addr }${ transaction_03__output_addr }${ transaction_03__funds }${ transaction_03__timestamp }`)
                .digest("hex")
        )
        .sign(user_03__keys.privateKey.export({ type: "pkcs1", format: "pem" }), "hex");
    
    const transaction_04__input_addr = "user_4";
    const transaction_04__output_addr = "user_5";
    const transaction_04__funds = 40;
    const transaction_04__timestamp = Date.now();
    const transaction_04__signature = crypto
        .createSign("SHA256")
        .update( 
            crypto.createHash("SHA256")
                .update(`${ transaction_04__input_addr }${ transaction_04__output_addr }${ transaction_04__funds }${ transaction_04__timestamp }`)
                .digest("hex")
        )
        .sign(user_04__keys.privateKey.export({ type: "pkcs1", format: "pem" }), "hex");
        
    const transaction_01 = new Transaction(transaction_01__input_addr, transaction_01__output_addr, transaction_01__funds, transaction_01__timestamp, transaction_01__signature);
    const transaction_02 = new Transaction(transaction_02__input_addr, transaction_02__output_addr, transaction_02__funds, transaction_02__timestamp, transaction_02__signature);
    const transaction_03 = new Transaction(transaction_03__input_addr, transaction_03__output_addr, transaction_03__funds, transaction_03__timestamp, transaction_03__signature);
    const transaction_04 = new Transaction(transaction_04__input_addr, transaction_04__output_addr, transaction_04__funds, transaction_04__timestamp, transaction_04__signature);

    console.log(`TRANSACTION #01 TESTING __START__\n\n${ transaction_01.to_string() }`);
    console.log(`signature verified: ${ transaction_01.verify_signature(user_01__keys.publicKey.export({ type: "pkcs1", format: "pem" })) }`);
    console.log(`hash verified: ${ transaction_01.verify_hash() }\n`);
    console.log(`TRANSACTION #01 TESTING __END__\n\n\n`);


    const blockchain = new Blockchain();

    const block_01 = blockchain.generate_block(
        [transaction_01, transaction_02], 
        user_01__keys
            .privateKey
            .export({ type: "pkcs1", format: "pem" })
    );

    const block_02 = blockchain.generate_block(
        [transaction_03], 
        user_02__keys
            .privateKey
            .export({ type: "pkcs1", format: "pem" })
    );

    const block_03 = blockchain.generate_block(
        [transaction_04], 
        user_03__keys
            .privateKey
            .export({ type: "pkcs1", format: "pem" })
    );

    console.log(`BLOCK #01 TESTING __START__\n\n${ block_01.to_string() }`);
    console.log(`signature verified: ${ block_01.verify_signature(user_01__keys.publicKey.export({ type: "pkcs1", format: "pem" })) }`);
    console.log(`hash verified: ${ block_01.verify_hash() }`);
    console.log(`merkle root verified: ${ block_01.verify_merkle_root() }\n`);
    console.log(`BLOCK #01 TESTING __END__\n\n\n`);



    console.log(`BLOCKCHAIN TESTING __START__\n`);
    console.log(`block's merkle root | last      : ${ blockchain.get_last_block().merkle_root }`);
    console.log(`block's merkle root | by index  : ${ blockchain.get_block_by_index(2).merkle_root }`);
    console.log(`block's merkle root | by hash   : ${ blockchain.get_block_by_hash(block_01.hash).merkle_root }\n`);
    console.log(`BLOCKCHAIN TESTING __END__\n\n`);
})(); 