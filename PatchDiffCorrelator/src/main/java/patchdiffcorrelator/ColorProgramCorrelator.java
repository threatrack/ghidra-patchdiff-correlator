package patchdiffcorrelator;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import generic.stl.Pair;

import static patchdiffcorrelator.AbstractColorProgramCorrelatorFactory.*;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelator;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ColorProgramCorrelator extends VTAbstractProgramCorrelator {
	private final String name;
	private final FunctionColorer colorer;
	private final ColorizingService colorService;

	public ColorProgramCorrelator(ServiceProvider serviceProvider, Program sourceProgram,
			AddressSetView sourceAddressSet, Program destinationProgram, AddressSetView destinationAddressSet,
			ToolOptions options, String name, FunctionColorer colorer) {
		super(serviceProvider, sourceProgram, sourceAddressSet, destinationProgram,
				destinationAddressSet, options);
		this.name = name;
		this.colorer = colorer;
		// FIXME: colorService is null
		this.colorService = serviceProvider.getService(ColorizingService.class);
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	protected void doCorrelate(VTMatchSet matchSet, TaskMonitor monitor) throws CancelledException {
		boolean only_color_bulk_matched = getOptions().getBoolean(ONLY_COLOR_BULK_MATCHED, ONLY_COLOR_BULK_MATCHED_DEFAULT);
	
		Program srcProg = getSourceProgram();
		Program dstProg = getDestinationProgram();

		FunctionIterator srcFuncIter = srcProg.getFunctionManager().getFunctions(getSourceAddressSet(), true);
		FunctionIterator dstFuncIter = dstProg.getFunctionManager().getFunctions(getDestinationAddressSet(), true);			

		monitor.setIndeterminate(false);

		// TODO: The count is wrong, in case matches are excluded :/
		monitor.initialize(srcProg.getFunctionManager().getFunctionCount() + dstProg.getFunctionManager().getFunctionCount());
		monitor.setMessage("(1/3) Get functions");

		HashMap<Address,List<Long>> srcHashMap = new HashMap<Address,List<Long>>();
		HashMap<Address,List<Long>> dstHashMap = new HashMap<Address,List<Long>>();

		while (!monitor.isCancelled() && srcFuncIter.hasNext()) {
			monitor.incrementProgress(1);
			Function func = srcFuncIter.next();
			if (!func.isThunk()) {
				srcHashMap.put(func.getEntryPoint(),null);
			}
		}
		
		while (!monitor.isCancelled() && dstFuncIter.hasNext()) {
			monitor.incrementProgress(1);
			Function func = dstFuncIter.next();
			if (!func.isThunk()) {
				dstHashMap.put(func.getEntryPoint(),null);
			}
		}

		HashSet<Pair<Address,Address>> diffSet = new HashSet<Pair<Address,Address>>();
		final VTSession session = matchSet.getSession();
		List<VTMatchSet> matchSets = session.getMatchSets();

		monitor.initialize(matchSets.size());
		monitor.setMessage("(2/3) Calculating coloring set (from accepted matches)");

		// TODO: optimize this
		for (VTMatchSet ms : matchSets) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			final Collection<VTMatch> matches = ms.getMatches();
			for(VTMatch match : matches)
			{
				VTAssociation a = match.getAssociation();
				Pair<Address,Address> addr = new Pair<Address,Address>(a.getSourceAddress(),a.getDestinationAddress());
				if( a.getStatus() == VTAssociationStatus.ACCEPTED &&
					a.getType() == VTAssociationType.FUNCTION &&
					srcHashMap.containsKey(addr.first) &&
					dstHashMap.containsKey(addr.second)
				)
				{
					if( only_color_bulk_matched && ! ms.getProgramCorrelatorInfo().getName().startsWith("Bulk") )
					{
						// don't add if not from a "Bulk" correlator match
						diffSet.remove(addr);
					}
					else
					{
						diffSet.add(addr);
					}
				}
			}
		}

		monitor.initialize(diffSet.size());
		monitor.setMessage("(3/3) Coloring...");
		
		for(Pair <Address,Address> addr : diffSet)
		{
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			Function srcFunc = getSourceProgram().getFunctionManager().getFunctionAt(addr.first);
			Function dstFunc = getDestinationProgram().getFunctionManager().getFunctionAt(addr.second);

			colorer.run(colorService, srcFunc, dstFunc, monitor);
		}
	}
	
}


