//Diffs the current function against a function in a different program and colors the differences.
//
//Useful after a Version Tracking Session to get a graph diff view.
//@author 
//@category Patch Diff
//@keybinding
//@menupath Tools.Patch Diff.Function Diff Colorizer
//@toolbar

import java.awt.Color;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import generic.stl.Pair;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FunctionDiffColorizer extends GhidraScript {

	private static final Color changedColor = new Color(200,180,180);

	@Override
	protected void run() throws Exception {
		ProgramManager programManager = getState().getTool().getService(ProgramManager.class);
		ColorizingService service = state.getTool().getService(ColorizingService.class);
		if (service == null) {
			println("Can't find ColorizingService service");
			return;
		}

		Program srcProgram = currentProgram;
		Function srcFunc = getFunctionAt(currentSelection.getMinAddress());
		String srcSymbolString = srcFunc.getSymbol().toString();

		// Get the dst function to compare against
		Program dstProgram = askProgram("Select Destination Program");
		int dstTransactionID = dstProgram.startTransaction("Dst FunctionDiffColorizer.java");
		try
		{
			List<String> askSymbolList = new ArrayList<String>();
			for( Symbol s : dstProgram.getSymbolTable().getAllSymbols(false) )
			{
				askSymbolList.add(s.toString());
			}
			String dstSymbolString = askChoice("Select Destination Function", "Select Destination Function", askSymbolList, srcSymbolString);
			Address dstAddress = null;
			for( Symbol s : dstProgram.getSymbolTable().getAllSymbols(false))
			{
				if(s.toString().equals(dstSymbolString))
					dstAddress = s.getAddress();
			}
			if( dstAddress == null )
			{
				throw new Exception("Could not get Destination function's address");
			}
			Function dstFunc = dstProgram.getFunctionManager().getFunctionAt(dstAddress);

			List<Pair<Long,AddressSetView>> srcList = hashes(srcProgram, srcFunc, monitor);
			List<Pair<Long,AddressSetView>> dstList = hashes(dstProgram, dstFunc, monitor);

			int s = 0;
			int d = 0;
			while( s<srcList.size() && d<dstList.size() )
			{
				Pair<Long,AddressSetView> src = srcList.get(s);
				Pair<Long,AddressSetView> dst = dstList.get(d);
				// TOOO: FIXME: this breaks on duplicate basic blocks
				int c = src.first.compareTo(dst.first);
				if( c<0 )
				{
					println("Src Different");
					programManager.setCurrentProgram(srcProgram);
					setBackgroundColor(src.second, changedColor);
					s++;
				}
				else if( c>0 )
				{
					println("Dst Different");
					programManager.setCurrentProgram(dstProgram);
					setBackgroundColor(dst.second, changedColor);
					d++;
				}
				else // c==0 
				{
					println("Not Different");
					s++;
					d++;
				}
			}
			while( s<srcList.size() )
			{
				Pair<Long,AddressSetView> src = srcList.get(s);
				println("Src Different");
				programManager.setCurrentProgram(srcProgram);
				setBackgroundColor(src.second, changedColor);
				s++;
			}
			while( d<srcList.size() )
			{
				Pair<Long,AddressSetView> dst = dstList.get(d);
				println("Dst Different");
				programManager.setCurrentProgram(dstProgram);
				setBackgroundColor(dst.second, changedColor);
				d++;
			}
		} finally {
			dstProgram.endTransaction(dstTransactionID, true);
		}

	}
	
	private List<Pair<Long,AddressSetView>> hashes(Program program, Function func, TaskMonitor monitor) throws CancelledException {
		List<Pair<Long,AddressSetView>> bbhashes = new ArrayList<>();
		
		CodeBlockModel blockModel = new BasicBlockModel(program);
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
			long bbhash = 0;
			for(long hash : hashes)
			{
				// TODO: use a proper hash
				bbhash = (bbhash*31 + hash);
			}
			Collections.sort(hashes);
			long bbhashBulk = 0;
			for(long hash : hashes)
			{
				// TODO: use a proper hash
				bbhashBulk = (bbhashBulk*31 + hash);
			}
			// TODO: FIXME: if the entry is a duplicate use bbhash
			bbhashes.add(new Pair<Long, AddressSetView>(bbhashBulk,block));
		}
		Collections.sort(bbhashes, new Comparator<Pair<Long, AddressSetView>>() {
		    public int compare(final Pair<Long, AddressSetView> a, final Pair<Long, AddressSetView> b) {
		    	return a.first.compareTo(b.first);
		    }
		});
		return bbhashes;
	}
}
