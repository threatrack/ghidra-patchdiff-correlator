**First prototype. Do not use in production!**

# Ghidra Patch Diff Correlator Project

This project tries to provide additional Ghidra Version Tracking Correlators suitable for patch diffing.

## How do I install it?

In Ghidra: `File` -> `Install Extensions` and select the `ghidra_9.1-BETA_DEV_20191010_PatchDiffCorrelator.zip`.

Then restart Ghidra.

## How to use?

**tl;dr:** Just select the `Bulk Instructions Match` Correlator when adding a Correlator to a Version Tracking Session.

**Full workflow:**

1. Run `Exact Function * Match` Correlators.
2. `Accept` all matched functions.
3. Run `Bulk Instructions Match`, but select `Exclude accepted matches`.
4. Order the functions by `Similarity` and go through starting from most similar, i.e., starting with score `1.000`.

## How does it work?

This adds additional Program Correlators to Ghidra. These are - unlike the
Correlators that ship with Ghidra - able to produce Matches with a Similarity Score
below `1.00`. This means these correlators give an estimate how similar functions
are to one another instead of providing perfect matching as the included correlators.

This indicator on similarity is need to find patches in functions.

### Bulk Instructions Match

The `Bulk Instructions Match` Correlator will make an unordered bulk list of Instructions
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

- `MOV        EBP,ESP`                                                           
- `MOV        ESP,EBP`                                                           
- `POP        EBP`                                                               
- `PUSH       EBP`                                                               
- `RET`  
- `SUB        ESP,0x8` 

If we now have a function:

```nasm
PUSH       EBP
MOV        EBP,ESP
SUB        ESP,0x42
MOV        ESP,EBP
POP        EBP
RET
```

With features:

- `MOV        EBP,ESP`                                                           
- `MOV        ESP,EBP`                                                           
- `POP        EBP`                                                               
- `PUSH       EBP`                                                               
- `RET`  
- `SUB        ESP,0x42` 

It would match 5 out of 6 features of the earlier function.

The matching is **unordered** - hence the notion of **"bulk"**.

So a function of (warning: doesn't make sense):

```nasm
SUB        ESP,0x8
POP        EBP
MOV        EBP,ESP
PUSH       EBP
MOV        ESP,EBP
RET
```

Would still match 6 of 6 with the original function, because of the unordered bulk
comparison logic.


### Bulk Mnemonics Match

The `Bulk Mnemonics Match` Correlator only adds the instruction mnemonics to the feature bundle for matching.

If you have the function:

```nasm
PUSH       EBP
MOV        EBP,ESP
SUB        ESP,0x8
MOV        ESP,EBP
POP        EBP
RET
```

Then the Correlator would "bulk" this to the following list of features:

- `MOV`                                                                          
- `MOV`                                                                          
- `POP`                                                                          
- `PUSH`                                                                         
- `RET` 
- `SUB`

If we now have a function:

```nasm
PUSH       EBP
MOV        EBP,ESP
SUB        ESP,0x42
MOV        ESP,EBP
POP        EBP
RET
```

With features:

- `MOV`                                                                          
- `MOV`                                                                          
- `POP`                                                                          
- `PUSH`                                                                         
- `RET` 
- `SUB`

would match 6 of 6.

Same unordered remarks as in the [Bulk Instructions Match] Correlator apply.

### TODO: Bulk Basic Block Mnemonics Match

The `Bulk Basic Block Program Correlator` isn't implemented yet, but it will be
the same as the Bulk Instruction Correlator, but the features in the bulk comparison will be basic
block hashes.

Getting basic blocks in Ghidra: <https://github.com/NationalSecurityAgency/ghidra/issues/1134>

## TODO

- Help of the Extension isn't available in Ghidra. Need to figure out how to fix that.
- Figure out how to use the masking feature in Ghidra and use it.
- Figure out this Ghidra bug(?): <https://github.com/NationalSecurityAgency/ghidra/issues/1135>


