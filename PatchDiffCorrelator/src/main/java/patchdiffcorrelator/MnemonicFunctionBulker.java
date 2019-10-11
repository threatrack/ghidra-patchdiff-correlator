package patchdiffcorrelator;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MnemonicFunctionBulker extends AbstractFunctionBulker {
	public static final MnemonicFunctionBulker INSTANCE = new MnemonicFunctionBulker();
	
	@Override
	public List<Long> hashes(Function func, TaskMonitor monitor) throws CancelledException {
		List<Long> hashes = new ArrayList<>();
		CodeUnitIterator iter = func.getProgram().getListing().getCodeUnits(func.getBody(), true);
		while (!monitor.isCancelled() && iter.hasNext()) {
			CodeUnit next = iter.next();
			//TODO: don't use hashCode()
			hashes.add((long) next.getMnemonicString().hashCode());
		}
		return hashes;
	}

}
