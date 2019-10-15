package patchdiffcorrelator;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface FunctionColorer {
	public void run(ColorizingService colorService, Function srcFunc, Function dstFunc, TaskMonitor monitor) throws CancelledException;
}
