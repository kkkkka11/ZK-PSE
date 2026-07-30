pragma circom 2.1.5;

include "@zk-email/zk-regex-circom/circuits/regex_helpers.circom";
include "./circom-regex/5{10,}.circom";
include "circomlib/circuits/poseidon.circom";

// SimpleRegexWithPoseidon 模板
template SimpleRegexWithPoseidon(maxLength) {
    signal input msg[maxLength];
    signal input k;
    signal output hash;
    signal output regex_match;

    signal regex_match5;

    // 第5个正则检查
    component regex_checker5 = SimpleRegex5(maxLength);  
    for (var i = 0; i < maxLength; i++) {
        regex_checker5.msg[i] <== msg[i];
    }
    regex_match5 <== regex_checker5.out;

    regex_match <== regex_match5;
    
    // 使用 Poseidon 哈希
    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== msg[0];
    poseidon.inputs[1] <== k;
    hash <== poseidon.out;

    // 约束：所有正则匹配必须成功
    regex_match === 1;
}

component main = SimpleRegexWithPoseidon(20);