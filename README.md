**First prototype. Do not use in production!**

# Ghidra Patch Diff Correlator Project

This project tries to provide additional Ghidra Version Tracking Correlators suitable for patch diffing.

## How do I install it?

In Ghidra: `File` -> `Install Extensions` and select the `ghidra_9.1-BETA_DEV_20191010_PatchDiffCorrelator.zip`.

Then restart Ghidra.

## How to use?

**A simple introduction video:**

[![Youtube video introducing the PatchDiffCorrelator Project](https://img.youtube.com/vi/8BH7ttwz5tg/0.jpg)](https://www.youtube.com/watch?v=8BH7ttwz5tg)

**Simple workflow:**

0. Run the Automatic Version Tracking Command.
1. Run a `Bulk * Match` Correlator with **`Only match accepted matches`** select. This will produce a scoring for your accepted matches for similarity of the functions.

**Advanced workflow:**

While the Automatic Version Tracking Command find very good matches by running
the included Correlators in their defined ordered and automagically accepting good
matching, it takes more time than only running the Correlators you need to get
your matches. This can be done via (but may vary depending on binary):

0. Run the `Exact Symbols Name Match` Correlator **if there are symbols**.
1. Run the `Exact Function * Match` Correlators.
2. `Accept` all matched functions.
3. `Accept` suitable `Implied Matches`
4. Run some `Reference` Correlators.
5. `Accept` matches.
6. **Repeat "conventional" matching until the function you are after has been accepted**.
7. Run a `Bulk * Match` Correlator with **`Only match accepted matches`** select. This will produce a scoring for your accepted matches for similarity of the functions.

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

### "Bulk" Correlators

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

### Coloring Correlators

These correlators color address ranges in the Source and Destination Programs
that are different.

#### ~~Abandoned: Coloring Basic Block Mnemonics~~

**State: This is a first work in progess prototype to see whether a correlator is
technically able to execute `setBackgroundColor()` on the Source and Destination Programs.**

This colors basic blocks that are either new or deleted or have a different
Mnemonic "Bulk" (see [Bulk Mnemonics Match] for a concept of "Bulk").

**Current issues:**
- Basic blocks are matched without CFG context.
- Fails badly if a function contains a duplicate basic block and the other program only contains the basic block once.
- **Version Tracking Correlators can't (and aren't supposed to) color programs**

**This is implemented as a script.**

### Other Correlators

- Recent paper summarizing the state of the art on binary code similarity: <https://arxiv.org/abs/1909.11424>

## Scripts

### FunctionDiffColorizer.java

1. Open Source Program.
2. Select Function to colorize in Destination Program.
3. Run `FunctionDiffColorizer.java`
	1. Select Destination Program.
	2. Select Destination Function.
4. The changes of the Destination Function in the Destination Program are now colored.

**Issues:**

- Unfortunately, it seems that after opening another program in a script `setBackgroundColor()`
  only works on that program and not the original program anymore.

## TODO

- In `BasicBlockMnemonicFunctionBulker.hashes()` use a proper hashing algorithm to hash the basic blocks.
- Optimization:
	- Use the `instruction prime products` concept of BinDiff (see <https://www.zynamics.com/bindiff/manual/>)
		- For this we need a mnemonic to prime number mapping :/
- Help of the Extension isn't available in Ghidra. Need to figure out how to fix that.
- Figure out this Ghidra bug(?): <https://github.com/NationalSecurityAgency/ghidra/issues/1135>
- Add option to only return the highest scoring match(es) for each function instead of the cross product of all functions.
- Use `symbol.getSource() == SourceType.DEFAULT` to detect undefined symbols instead of `.startswith("FUN_"`.
- Either add masking to the `Instructions` bulker, e.g. via:

```python
from ghidra.app.plugin.core.instructionsearch import InstructionSearchApi
from ghidra.app.plugin.core.instructionsearch.model import MaskSettings
InstructionSearchApi().getBinarySearchString(currentProgram,currentSelection.getFirstRange(),MaskSettings(False,False,True))
```

- ... or remove the `Instructions` bulker ... because it is kind of useless without masking.

- Make FunctionDiffColorizer.java color both source and destination program!


