pragma circom 2.1.5;

include "@zk-email/zk-regex-circom/circuits/regex_helpers.circom";
include "./simple_regex.circom";
include "circomlib/circuits/poseidon.circom";

template PasswordHash20() {
    signal input msg[20];
    signal input k;
    signal output hash;

    component left_hasher = Poseidon(10);
    component right_hasher = Poseidon(10);
    component final_hasher = Poseidon(3);

    for (var i = 0; i < 10; i++) {
        left_hasher.inputs[i] <== msg[i];
        right_hasher.inputs[i] <== msg[i + 10];
    }

    final_hasher.inputs[0] <== k;
    final_hasher.inputs[1] <== left_hasher.out;
    final_hasher.inputs[2] <== right_hasher.out;

    hash <== final_hasher.out;
}

template SimpleRegexWithPoseidon(msg_bytes) {
    signal input msg[msg_bytes];
    signal input k;
    signal output hash;
    signal output regex_match;

    // 直接使用原始生成的SimpleRegex模板
    component regex_checker = SimpleRegex(msg_bytes);
    for (var i = 0; i < msg_bytes; i++) {
        regex_checker.msg[i] <== msg[i];
    }
    regex_match <== regex_checker.out;

    // 使用与手写组合电路一致的分块 Poseidon 哈希，绑定完整 msg 和 k
    component password_hash = PasswordHash20();
    for (var i = 0; i < msg_bytes; i++) {
        password_hash.msg[i] <== msg[i];
    }
    password_hash.k <== k;
    hash <== password_hash.hash;
}

component main = SimpleRegexWithPoseidon(20);