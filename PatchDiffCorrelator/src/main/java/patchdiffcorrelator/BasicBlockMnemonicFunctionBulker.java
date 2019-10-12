package patchdiffcorrelator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class BasicBlockMnemonicFunctionBulker extends AbstractFunctionBulker {
	public static final BasicBlockMnemonicFunctionBulker INSTANCE = new BasicBlockMnemonicFunctionBulker();
	
	@Override
	public List<Long> hashes(Function func, TaskMonitor monitor) throws CancelledException {
		List<Long> bbhashes = new ArrayList<>();
		
		CodeBlockModel blockModel = new BasicBlockModel(func.getProgram());
		AddressSetView addresses = func.getBody();
		CodeBlockIterator bbiter = blockModel.getCodeBlocksContaining(addresses, monitor);
		
		while (!monitor.isCancelled() && bbiter.hasNext() )
		{
			CodeBlock block = bbiter.next();
			List<Long> hashes = new ArrayList<>();
			CodeUnitIterator iter = func.getProgram().getListing().getCodeUnits(block, true);
			while (!monitor.isCancelled() && iter.hasNext()) {
				CodeUnit next = iter.next();
				//TODO: don't use hashCode()
				hashes.add((long) next.getMnemonicString().hashCode());
			}
			/* sort the mnemonics so:
			 * PUSH       EBP
			 * MOV        EBP,ESP
			 * SUB        ESP,0x42
			 * MOV        ESP,EBP
			 * POP        EBP
			 * RET
			 * 
			 * becomes:
			 * MOV
			 * MOV
			 * POP
			 * PUSH
			 * RET
			 * SUB
			 * 
			 * this helps with cases were the compiler swaps instructions
			 */
			Collections.sort(hashes);
			/* hash over the sorted mnemonics, so each bbhash has the mnemonics of
			 * that basic block encoded
			 */
			long bbhash = 0;
			for(long hash : hashes)
			{
				bbhash = (bbhash + hash);
			}
			bbhashes.add(bbhash);
		}
		return bbhashes;
	}

}
