package patchdiffcorrelator;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class InstructionFunctionBulker extends AbstractFunctionBulker {
	public static final InstructionFunctionBulker INSTANCE = new InstructionFunctionBulker();
	
	@Override
	public List<Long> hashes(Function func, TaskMonitor monitor) throws CancelledException {
		List<Long> hashes = new ArrayList<>();
		
		CodeUnitIterator iter = func.getProgram().getListing().getCodeUnits(func.getBody(), true);
		while (!monitor.isCancelled() && iter.hasNext()) {
			CodeUnit next = iter.next();
			// TODO: mask the immediate and displacement values in instructions
			hashes.add((long) next.toString().hashCode());
			//System.out.println(next.toString() + " = " + next.toString().hashCode());
		}
		return hashes;
	}

}
