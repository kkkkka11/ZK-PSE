pragma circom 2.1.5;

include "@zk-email/zk-regex-circom/circuits/regex_helpers.circom";
include "./circom-regex/[!@#$%^&*].circom";
include "circomlib/circuits/poseidon.circom";

// SimpleRegexWithPoseidon 模板
template SimpleRegexWithPoseidon(maxLength) {
    signal input msg[maxLength];  // 输入信号 msg，长度由 maxLength 控制
    signal input k;
    signal output hash;
    signal output regex_match;

    // 直接使用原始生成的 SimpleRegex 模板
    component regex_checker = SimpleRegex(maxLength);  // 调用 SimpleRegex 模板，传入 maxLength
    for (var i = 0; i < maxLength; i++) {
        regex_checker.msg[i] <== msg[i];  // 填充 regex_checker 的输入
    }
    regex_match <== regex_checker.out;  // 将 regex 检查的结果传给 output

    // 使用 Poseidon 哈希
    component poseidon = Poseidon(2);  // 假设你选择 Poseidon
    poseidon.inputs[0] <== msg[0];  // 将 msg 的第一个元素传递给 Poseidon
    poseidon.inputs[1] <== k;  // 假设 k 是哈希的另一个输入
    hash <== poseidon.out;  // 输出哈希值

    // 检查正则匹配是否成功
    regex_match === 1;  // 如果正则匹配失败，电路会报错
}

// 调用 SimpleRegexWithPoseidon 模板并传递具体的长度和消息
component main = SimpleRegexWithPoseidon(32); // 这里传入 32 个字符长度
