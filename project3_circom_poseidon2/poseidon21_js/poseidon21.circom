pragma circom 2.1.4;

include "/home/zhangchi/circomlib/circuits/poseidon.circom";

template PoseidonHash2() {
    signal input in[2];
    signal output out;

    component p = Poseidon(2);

    for (var i = 0; i < 2; i++) {
        p.inputs[i] <== in[i];
    }


    out <== p.out;
}

component main = PoseidonHash2();

