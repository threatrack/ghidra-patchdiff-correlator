**First prototype. Do not use in production!**

# Ghidra Patch Diff Correlator Project

This project tries to provide additional Ghidra Version Tracking Correlators suitable for patch diffing.

## How do I install it?

In Ghidra: `File` -> `Install Extensions` and select the `ghidra_9.1-BETA_DEV_20191010_PatchDiffCorrelator.zip`.

Then restart Ghidra.

## How to use?

Just select the `Bulk Instructions Match` Correlator when adding a Correlator to a Version Tracking Session.

## How does it work?

This adds additional Program Correlators to Ghidra. These are - unlike the
Correlators that ship with Ghidra - able to produce Matches with a Similarity Score
below `1.00`. This means these correlators give an estimate how similar functions
are to one another instead of providing perfect matching as the included correlators.

This indicator on similarity is need to find patches in functions.

### Bulk Instruction Program Correlator

The `Bulk Instruction Program Correlator` will make an unordered bulk list of Instructions
occurring in a function.

Let's say we have the function:

```nasm
PUSH       EBP
MOV        EBP,ESP
SUB        ESP,0x8
MOV        ESP,EBP
POP        EBP
RET
```

Then the Correlator would "bulk" this to the following list of features:

- `PUSH       EBP`
- `MOV        EBP,ESP`
- `SUB        ESP,0x8`
- `MOV        ESP,EBP`
- `POP        EBP`
- `RET`

If we now have a function:

```nasm
PUSH       EBP
MOV        EBP,ESP
MOV        ESP,EBP
POP        EBP
RET
```

With features:

- `PUSH       EBP`
- `MOV        EBP,ESP`
- `MOV        ESP,EBP`
- `POP        EBP`
- `RET`

It would match 5 out of 6 features of the earlier function.

The matching is **unordered** - hence the notion of **"bulk"**.

So a function of (warning: doesn't make sense):

```nasm
POP        EBP
MOV        EBP,ESP
MOV        ESP,EBP
SUB        ESP,0x8
PUSH       EBP
RET
```

Would still match 6 of 6 with the original function, because of the unordered bulk
comparison logic.

**Eventually, proper state-of-the-art CFG based algorithms should be implemented, but as a
start this is already an improvement over the binary-only Correlators.**

### Bulk Basic Block Program Correlator

The `Bulk Basic Block Program Correlator` isn't implemented yet, but it will be
the same as the Bulk Instruction Correlator, but the features in the bulk comparison will be basic
block hashes.


## TODO

- Help of the Extension isn't available in Ghidra. Need to figure out how to fix that.


