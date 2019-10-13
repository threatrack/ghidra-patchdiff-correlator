**First prototype. Do not use in production!**

# Ghidra Patch Diff Correlator Project

This project tries to provide additional Ghidra Version Tracking Correlators suitable for patch diffing.

## How do I install it?

In Ghidra: `File` -> `Install Extensions` and select the `ghidra_9.1-BETA_DEV_20191010_PatchDiffCorrelator.zip`.

Then restart Ghidra.

## How to use?

**Full workflow:**

0. Run the `Exact Symbols Name Match` Correlator **if there are symbols**.
1. Run the `Exact Function * Match` Correlators.
2. `Accept` all matched functions.
3. `Accept` suitable `Implied Matches`
4. Run some `Reference` Correlators.
5. `Accept` matches.
6. **Repeat "conventional" matching until the function you are after has been accepted**.
7. Run a `Bulk * Match` with **`Only match accepted matches`** select. This will produce a scoring for your accepted matches for similarity of the functions.

### Hints

- The symbol matcher in these correlators is not as good as the included `Exact Symbols Name Match` Correlator.
- These matchers are slower than the included `Exact Function * Match` Correlators, so you should run the included ones first, then exclude them (via selection) from running through the patch diff correlators.
- The `Bulk Basic Block Mnemonics Match` Correlator is good for finding basic block changes.
- The `Bulk Mnemomics Match` Correlator is robust against instruction reordering performed by compilers.

## How does it work?

This adds additional Program Correlators to Ghidra. These are - unlike the
Correlators that ship with Ghidra - able to produce Matches with a Similarity Score
below `1.00`. This means these correlators give an estimate how similar functions
are to one another instead of providing perfect matching as the included correlators.

This indicator on similarity is need to find patches in functions.

### Correlators

#### Bulk Instructions Match

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


#### Bulk Mnemonics Match

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

#### Bulk Basic Block Mnemonics Match

The `Bulk Basic Block Mnemonics Match` Correlator first converts the mnemonics
of each basic block into a list. That list is sorted and hashes (so the order of the mnemonics
within the basic block don't matter). Then these basic block hashes are compared
between functions in an unordered bulk comparison.

### Options

There are several options:

- `Minimum similarity threshold (score)`: Only return matches that have a score higher than this threshold.
- `Minimum confidence threshold (score)`: Confidence is ranked as follows (but may change in the future):
	- `1.0` or `0.000` in `log10`: When symbols don't match
	- `10.0` or `1.000` in `log10`: When symbols match
- `Symbol names must match`: Only match functions when their symbol names match
	- **Warning:** If you disable this make sure to set `Minimum similarity threshold` to something reasonable, otherwise you get the cross-product of all the functions in both binaries, e.g. if the source program has 100 functions and the destination also 100 and no threshold is specified, you'd get `100 * 100 = 100000` matches!
- `Ignore undefined symbols (FUN_)`: Settings this won't use the default labels assigned to undefined symbols for symbol name matching. So it won't match `FUN_00001234` to `FUN_00001234`.
- `Only match accepted matches`: Only calculate the similarity for functions that already have an accepted match entry in the Matches Table. **This is the most useful option.**

### Other Correlators

- Recent paper summarizing the state of the art on binary code similarity: <https://arxiv.org/abs/1909.11424>

## TODO

- Help of the Extension isn't available in Ghidra. Need to figure out how to fix that.
- Figure out how to use the masking feature in Ghidra and use it.
- Figure out this Ghidra bug(?): <https://github.com/NationalSecurityAgency/ghidra/issues/1135>
- Add option to only return the highest scoring match(es) for each function instead of the cross product of all functions.
- In `BasicBlockMnemonicFunctionBulker.hashes()` use a proper hashing algorithm to hash the basic blocks.
- Use `symbol.getSource() == SourceType.DEFAULT` to detect undefined symbols instead of `.startswith("FUN_"`.

