pragma circom 2.2.3;

// Smallest useful circuit: one constraint, one public output.
template Multiplier() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
}

component main = Multiplier();
