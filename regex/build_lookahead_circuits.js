#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const DEFAULT_MSG_BYTES = 20;
const VENDORED_ZK_REGEX_ROOT = path.join(__dirname, "zk-regex-compiler-v2");
const VENDORED_ZK_REGEX_BIN = path.join(VENDORED_ZK_REGEX_ROOT, "target/release/zk-regex");
const LOCAL_ZK_REGEX_BIN = path.join(__dirname, "target/release/zk-regex");

function resolveZkRegexBin() {
    if (process.env.ZK_REGEX_BIN) {
        return process.env.ZK_REGEX_BIN;
    }
    if (fs.existsSync(VENDORED_ZK_REGEX_BIN)) {
        return VENDORED_ZK_REGEX_BIN;
    }
    if (fs.existsSync(path.join(VENDORED_ZK_REGEX_ROOT, "Cargo.toml"))) {
        throw new Error(`Patched zk-regex compiler is present but not built. Run: cargo build --release -p zk-regex-compiler --bin zk-regex --manifest-path ${path.join(VENDORED_ZK_REGEX_ROOT, "Cargo.toml")}`);
    }
    return fs.existsSync(LOCAL_ZK_REGEX_BIN) ? LOCAL_ZK_REGEX_BIN : "zk-regex";
}

let ZK_REGEX_BIN;

function usage() {
    console.log(`Usage:
  node build_lookahead_circuits.js <rules.txt> [output_dir] [--compile] [--verbose] [--dot utf8|ascii] [--shared-input true|false] [--no-shared-input] [--gen-substrs]

Input format:
  Regex 1: ^(?=.*[a-z])(?=.*[A-Z]).{10,}$;
  Regex 2: ^(?=.*[A-Z]).{11,}$;

Supported first-pass syntax:
  - Positive lookahead: (?=.*X)
  - Negative lookahead: (?!.*X)
  - Tail minimum length: .{10,}, .{11,}
  - Max-only .{,20} / .{0,20} is treated as satisfied by msg[20]

Dot modes:
  --dot utf8   Keep .{N,} as a UTF-8 character regex. This is the default.
  --dot ascii  Lower .{N,} tail checks to printable ASCII [ -~]{N,}.

Experiment toggles:
  --shared-input true   Use one shared byte input for all DFA subcircuits. This is the default.
  --shared-input false  Let each generated DFA subcircuit build and range-check its own input.
  --no-shared-input     Alias for --shared-input false.
  --gen-substrs         Keep zk-regex substring/reveal helper logic instead of -g false.

This generator lowers password-policy lookaheads into independent zk-regex
subcircuits and combines their boolean outputs in a wrapper circuit.

Environment:
  ZK_REGEX_BIN  Path to a zk-regex binary. By default, this script uses the
                patched vendored v2 compiler under regex/zk-regex-compiler-v2.
                Shared-input circuits are produced by deterministic post-processing.`);
}

function run(command, options = {}) {
    if (options.verbose) {
        console.log(`$ ${command}`);
    }
    return execSync(command, {
        encoding: "utf8",
        stdio: options.verbose || options.inheritOutput ? "inherit" : "pipe",
        cwd: options.cwd || process.cwd(),
    });
}

function normalizeRawRegex(regex) {
    return regex
        .replace(/ˆ/g, "^")
        .replace(/\r/g, "")
        .replace(/\s+/g, "")
        .replace(/;$/, "");
}

function parseRulesFile(filePath) {
    const text = fs.readFileSync(filePath, "utf8").replace(/\r/g, "");
    const rules = [];
    const re = /Regex\s+(\d+)\s*:\s*([\s\S]*?)(?=(?:\n?\s*Regex\s+\d+\s*:)|$)/g;
    let match;
    while ((match = re.exec(text)) !== null) {
        const id = match[1];
        const regex = normalizeRawRegex(match[2]);
        if (regex.length > 0) {
            rules.push({ id, regex });
        }
    }

    if (rules.length === 0) {
        throw new Error("No rules found. Expected lines like `Regex 1: ...;`.");
    }
    return rules;
}

function readBalancedGroup(text, start) {
    if (text[start] !== "(") {
        throw new Error(`Expected '(' at index ${start}`);
    }

    let depth = 0;
    let escaped = false;
    for (let i = start; i < text.length; i++) {
        const ch = text[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (ch === "\\") {
            escaped = true;
            continue;
        }
        if (ch === "(") depth += 1;
        if (ch === ")") depth -= 1;
        if (depth === 0) {
            return {
                content: text.slice(start + 1, i),
                end: i + 1,
            };
        }
    }

    throw new Error(`Unbalanced group starting at index ${start}`);
}

function extractLookaheads(regex, options = {}) {
    const conditions = [];
    let tail = "";
    let cursor = 0;

    while (cursor < regex.length) {
        const next = regex.indexOf("(?", cursor);
        if (next === -1) {
            tail += regex.slice(cursor);
            break;
        }

        tail += regex.slice(cursor, next);
        const group = readBalancedGroup(regex, next);
        const content = group.content;

        if (content.startsWith("?=")) {
            for (const conditionRegex of normalizeConditionRegexes(content.slice(2), false)) {
                conditions.push({
                    negate: false,
                    regex: conditionRegex,
                    source: regex.slice(next, group.end),
                });
            }
        } else if (content.startsWith("?!")) {
            for (const conditionRegex of normalizeConditionRegexes(content.slice(2), true)) {
                conditions.push({
                    negate: true,
                    regex: conditionRegex,
                    source: regex.slice(next, group.end),
                });
            }
        } else {
            tail += regex.slice(next, group.end);
        }

        cursor = group.end;
    }

    addTailCondition(tail, conditions, options);
    return conditions;
}

function stripOuterParens(value) {
    if (!(value.startsWith("(") && value.endsWith(")"))) {
        return value;
    }
    try {
        const group = readBalancedGroup(value, 0);
        if (group.end === value.length) {
            return group.content;
        }
    } catch (_) {
        return value;
    }
    return value;
}

function normalizeConditionRegexes(regex, negate) {
    let out = regex;

    while (out.startsWith(".*")) {
        out = out.slice(2);
    }
    out = stripOuterParens(out);
    out = out.replace(/\\d/g, "[0-9]");

    if (/^\[[!@#$%^&*]+\]$/.test(out) || /^\[[!%^@#$&*]+\]$/.test(out)) {
        return ["\\!|\\@|\\#|\\$|\\%|\\^|\\&|\\*"];
    }

    return [out];
}

function addTailCondition(tail, conditions, options = {}) {
    const anchored = tail.startsWith("^") && tail.endsWith("$");
    const dotMode = options.dot || "utf8";
    let out = tail.replace(/^\^/, "").replace(/\$$/, "");
    if (out === "") {
        return;
    }
    if (out === ".*") {
        if (dotMode === "ascii") {
            conditions.push({
                negate: false,
                regex: anchored ? "^[ -~]*$" : "[ -~]*",
                source: tail,
            });
        }
        return;
    }

    out = out.replace(/^\./, ".");
    if (out === ".{,20}" || out === ".{0,20}") {
        return;
    }

    const minLength = out.match(/^\.\{(\d+),\}$/);
    if (minLength) {
        const anyChar = dotMode === "ascii" ? "[ -~]" : ".";
        const regex = anchored
            ? `^${anyChar}{${minLength[1]},}$`
            : `${anyChar}{${minLength[1]},}`;
        conditions.push({
            negate: false,
            regex,
            source: tail,
        });
        return;
    }

    throw new Error(`Unsupported non-lookahead tail: ${tail}`);
}

function sanitizeName(value) {
    return value.replace(/[^A-Za-z0-9_]/g, "_").replace(/^([0-9])/, "_$1");
}

function writeRegexJson(jsonPath, regex) {
    fs.writeFileSync(
        jsonPath,
        JSON.stringify(
            {
                parts: [
                    {
                        is_public: false,
                        regex_def: regex,
                    },
                ],
            },
            null,
            2
        )
    );
}

function parseDotMode(args) {
    const index = args.indexOf("--dot");
    if (index === -1) {
        return "utf8";
    }
    const value = args[index + 1];
    if (value !== "utf8" && value !== "ascii") {
        throw new Error("--dot must be either `utf8` or `ascii`.");
    }
    return value;
}

function parseSharedInput(args) {
    if (args.includes("--no-shared-input")) {
        return false;
    }

    const index = args.indexOf("--shared-input");
    if (index === -1) {
        return true;
    }

    const value = args[index + 1];
    if (value === "false" || value === "0" || value === "no") {
        return false;
    }
    if (value === undefined || value.startsWith("--") || value === "true" || value === "1" || value === "yes") {
        return true;
    }

    throw new Error("--shared-input must be `true` or `false`.");
}

function positionalArgs(args) {
    const positionals = [];
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (arg === "--dot") {
            i += 1;
            continue;
        }
        if (arg === "--shared-input") {
            const value = args[i + 1];
            if (value !== undefined && !value.startsWith("--")) {
                i += 1;
            }
            continue;
        }
        if (arg.startsWith("--")) {
            continue;
        }
        positionals.push(arg);
    }
    return positionals;
}

function braceDelta(content) {
    let delta = 0;
    let escaped = false;
    let inString = null;

    for (const ch of content) {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (ch === "\\") {
            escaped = true;
            continue;
        }
        if (inString) {
            if (ch === inString) {
                inString = null;
            }
            continue;
        }
        if (ch === "\"" || ch === "'") {
            inString = ch;
            continue;
        }
        if (ch === "{") delta += 1;
        if (ch === "}") delta -= 1;
    }

    return delta;
}

function repairGeneratedCircom(circomPath) {
    const content = fs.readFileSync(circomPath, "utf8");
    const delta = braceDelta(content);

    if (delta === 0) {
        return;
    }
    if (delta === 1 && !content.trimEnd().endsWith("}")) {
        fs.writeFileSync(circomPath, `${content}\n}\n`);
        return;
    }

    throw new Error(`Generated Circom has unbalanced braces: ${circomPath}`);
}


function convertGeneratedCircomToSharedInput(circomPath) {
    const content = fs.readFileSync(circomPath, "utf8");
    const inputBlock = /\n\s*signal input msg\[msg_bytes\];\n\s*signal output out;\n\n\s*var num_bytes = msg_bytes\+1;\n\s*signal in\[num_bytes\];\n\s*signal in_range_checks\[msg_bytes\];\n\s*in\[0\]\s*<==\s*255;\n\s*for \(var i = 0; i < msg_bytes; i\+\+\) \{\n\s*in_range_checks\[i\]\s*<==\s*LessThan\(8\)\(\[msg\[i\], 255\]\);\n\s*in_range_checks\[i\]\s*===\s*1;\n\s*in\[i\+1\]\s*<==\s*msg\[i\];\n\s*\}\n/;
    const replacement = `
\tsignal input in[msg_bytes+1];
\tsignal output out;

\tvar num_bytes = msg_bytes+1;
`;
    const updated = content.replace(inputBlock, replacement);

    if (updated === content) {
        throw new Error(`Failed to convert generated DFA to shared-input interface: ${circomPath}`);
    }
    if (updated.includes("signal input msg[msg_bytes]") || updated.includes("in_range_checks")) {
        throw new Error(`Shared-input conversion left duplicated input checks in: ${circomPath}`);
    }

    fs.writeFileSync(circomPath, updated);
}

function generateSubCircuit(condition, index, ruleDir, options) {
    const templateName = `RuleCond${index}`;
    const baseName = `cond_${String(index).padStart(2, "0")}_${sanitizeName(condition.regex).slice(0, 48)}`;
    const jsonPath = path.join(ruleDir, `${baseName}.json`);
    const circomPath = path.join(ruleDir, `${baseName}.circom`);

    writeRegexJson(jsonPath, condition.regex);
    const genSubstrs = options.genSubstrs ? "true" : "false";
    run(
        `${JSON.stringify(ZK_REGEX_BIN)} decomposed -d ${JSON.stringify(jsonPath)} -c ${JSON.stringify(circomPath)} -t ${templateName} -g ${genSubstrs}`,
        options
    );
    repairGeneratedCircom(circomPath);
    if (options.sharedInput) {
        convertGeneratedCircomToSharedInput(circomPath);
        repairGeneratedCircom(circomPath);
    }

    return {
        ...condition,
        templateName,
        circomPath,
        includePath: `./${path.basename(circomPath)}`,
    };
}

function passwordHashTemplate() {
    return `template PasswordHash20Salt20() {
    signal input msg[20];
    signal input salt[20];
    signal output hash;

    component msg_left_hasher = Poseidon(10);
    component msg_right_hasher = Poseidon(10);
    component salt_left_hasher = Poseidon(10);
    component salt_right_hasher = Poseidon(10);
    component final_hasher = Poseidon(4);

    for (var i = 0; i < 10; i++) {
        msg_left_hasher.inputs[i] <== msg[i];
        msg_right_hasher.inputs[i] <== msg[i + 10];
        salt_left_hasher.inputs[i] <== salt[i];
        salt_right_hasher.inputs[i] <== salt[i + 10];
    }

    final_hasher.inputs[0] <== msg_left_hasher.out;
    final_hasher.inputs[1] <== msg_right_hasher.out;
    final_hasher.inputs[2] <== salt_left_hasher.out;
    final_hasher.inputs[3] <== salt_right_hasher.out;

    hash <== final_hasher.out;
}`;
}

function connectCheckerInputSnippet(checkerName, options) {
    const lines = [];
    if (options.sharedInput) {
        lines.push(`    for (var j = 0; j <= maxLength; j++) {`);
        lines.push(`        ${checkerName}.in[j] <== shared_in[j];`);
        lines.push(`    }`);
    } else {
        lines.push(`    for (var j = 0; j < maxLength; j++) {`);
        lines.push(`        ${checkerName}.msg[j] <== msg[j];`);
        lines.push(`    }`);
    }
    return lines.join("\n");
}

function combineConditionsSnippet(conditions, options) {
    const lines = [];
    lines.push(`    signal condition_out[${conditions.length}];`);
    for (let i = 0; i < conditions.length; i++) {
        lines.push(`    component checker_${i} = ${conditions[i].templateName}(maxLength);`);
        lines.push(connectCheckerInputSnippet(`checker_${i}`, options));
        if (conditions[i].negate) {
            lines.push(`    condition_out[${i}] <== 1 - checker_${i}.out;`);
        } else {
            lines.push(`    condition_out[${i}] <== checker_${i}.out;`);
        }
        lines.push("");
    }

    if (conditions.length === 1) {
        lines.push(`    regex_match <== condition_out[0];`);
    } else {
        lines.push(`    signal and_acc[${conditions.length - 1}];`);
        lines.push(`    and_acc[0] <== condition_out[0] * condition_out[1];`);
        for (let i = 2; i < conditions.length; i++) {
            lines.push(`    and_acc[${i - 1}] <== and_acc[${i - 2}] * condition_out[${i}];`);
        }
        lines.push(`    regex_match <== and_acc[${conditions.length - 2}];`);
    }

    return lines.join("\n");
}

function generateWrapper(rule, conditions, ruleDir, options) {
    const includes = conditions.map((condition) => `include "${condition.includePath}";`).join("\n");
    const wrapperName = `GeneratedRegex${rule.id}`;
    const wrapperPath = path.join(ruleDir, `${wrapperName}.circom`);

    const sourceComments = conditions
        .map(
            (condition, index) =>
                `// condition ${index}: ${condition.negate ? "NOT " : ""}${condition.regex}  (from ${condition.source})`
        )
        .join("\n");
    const sharedInputSnippet = options.sharedInput
        ? `    var num_bytes = maxLength + 1;
    signal shared_in[num_bytes];
    signal in_range_checks[maxLength];

    shared_in[0] <== 255;
    for (var i = 0; i < maxLength; i++) {
        in_range_checks[i] <== LessThan(8)([msg[i], 255]);
        in_range_checks[i] === 1;
        shared_in[i + 1] <== msg[i];
    }`
        : "";

    const content = `pragma circom 2.1.5;

${includes}
include "@zk-email/zk-regex-circom/circuits/regex_helpers.circom";
include "circomlib/circuits/poseidon.circom";

${sourceComments}

${passwordHashTemplate()}

template ${wrapperName}(maxLength) {
    signal input msg[maxLength];
    signal input salt[20];
    signal input expected_match;
    signal output hash;
    signal output regex_match;
    signal salt_range_checks[20];

    for (var s = 0; s < 20; s++) {
        salt_range_checks[s] <== LessThan(9)([salt[s], 256]);
        salt_range_checks[s] === 1;
    }

${sharedInputSnippet}

${combineConditionsSnippet(conditions, options)}

    component password_hash = PasswordHash20Salt20();
    for (var i = 0; i < maxLength; i++) {
        password_hash.msg[i] <== msg[i];
    }
    for (var s = 0; s < 20; s++) {
        password_hash.salt[s] <== salt[s];
    }
    hash <== password_hash.hash;

    expected_match * (expected_match - 1) === 0;
    regex_match === expected_match;
}

component main { public [expected_match] } = ${wrapperName}(${DEFAULT_MSG_BYTES});
`;

    fs.writeFileSync(wrapperPath, content);

    if (options.compile) {
        const compileDir = path.join(ruleDir, "build");
        fs.mkdirSync(compileDir, { recursive: true });
        run(
            `circom -l node_modules ${JSON.stringify(wrapperPath)} --r1cs --wasm --sym --O0 -o ${JSON.stringify(compileDir)}`,
            { ...options, inheritOutput: true }
        );
    }

    return wrapperPath;
}

function buildRule(rule, outputDir, options) {
    const ruleDir = path.join(outputDir, `regex_${rule.id}`);
    fs.rmSync(ruleDir, { recursive: true, force: true });
    fs.mkdirSync(ruleDir, { recursive: true });

    const conditions = extractLookaheads(rule.regex, options);
    if (conditions.length === 0) {
        throw new Error(`Regex ${rule.id} produced no conditions.`);
    }

    const generated = conditions.map((condition, index) =>
        generateSubCircuit(condition, index, ruleDir, options)
    );
    const wrapperPath = generateWrapper(rule, generated, ruleDir, options);

    fs.writeFileSync(
        path.join(ruleDir, "metadata.json"),
        JSON.stringify(
            {
                id: rule.id,
                source_regex: rule.regex,
                msg_bytes: DEFAULT_MSG_BYTES,
                salt_bytes: 20,
                salt_encoding: "hex",
                dot_mode: options.dot,
                shared_input: options.sharedInput,
                gen_substrs: options.genSubstrs,
                wrapper: path.basename(wrapperPath),
                conditions: generated.map(({ regex, negate, source, templateName, includePath }) => ({
                    regex,
                    negate,
                    source,
                    templateName,
                    includePath,
                })),
            },
            null,
            2
        )
    );

    console.log(`Generated regex ${rule.id}: ${wrapperPath}`);
}

function main() {
    const args = process.argv.slice(2);
    if (args.length === 0 || args.includes("--help")) {
        usage();
        return;
    }

    ZK_REGEX_BIN = resolveZkRegexBin();

    const positionals = positionalArgs(args);
    const inputPath = path.resolve(positionals[0]);
    const outputDir = path.resolve(positionals[1] || "./generated-lookahead");
    const options = {
        compile: args.includes("--compile"),
        verbose: args.includes("--verbose"),
        dot: parseDotMode(args),
        sharedInput: parseSharedInput(args),
        genSubstrs: args.includes("--gen-substrs"),
        cwd: process.cwd(),
    };

    fs.mkdirSync(outputDir, { recursive: true });
    const rules = parseRulesFile(inputPath);
    for (const rule of rules) {
        buildRule(rule, outputDir, options);
    }
}

if (require.main === module) {
    try {
        main();
    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
}
