package patchdiffcorrelator;

import java.util.List;

import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface FunctionBulker {
	public List<Long> hashes(Function function, TaskMonitor monitor) throws CancelledException;
}
