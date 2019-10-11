package patchdiffcorrelator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static patchdiffcorrelator.BulkInstructionProgramCorrelatorFactory.*;

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

public class BulkProgramCorrelator extends VTAbstractProgramCorrelator {
	private final String name;
	private final FunctionBulker bulker;
	
	public BulkProgramCorrelator(ServiceProvider serviceProvider, Program sourceProgram,
			AddressSetView sourceAddressSet, Program destinationProgram, AddressSetView destinationAddressSet,
			ToolOptions options, String name, FunctionBulker bulker) {
		super(serviceProvider, sourceProgram, sourceAddressSet, destinationProgram,
				destinationAddressSet, options);
		this.name = name;
		this.bulker = bulker;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	protected void doCorrelate(VTMatchSet matchSet, TaskMonitor monitor) throws CancelledException {
		double similarity_threshold = getOptions().getDouble(SIMILARITY_THRESHOLD, SIMILARITY_THRESHOLD_DEFAULT);
		double confidence_threshold = getOptions().getDouble(CONFIDENCE_THRESHOLD, CONFIDENCE_THRESHOLD_DEFAULT);
		boolean symbol_names_must_match = getOptions().getBoolean(SYMBOL_NAMES_MUST_MATCH, SYMBOL_NAMES_MUST_MATCH_DEFAULT);

		VTMatchInfo matchInfo = new VTMatchInfo(matchSet);
		
		Program srcProg = getSourceProgram();
		Program dstProg = getDestinationProgram();
		
		FunctionIterator srcFuncIter = srcProg.getFunctionManager().getFunctions(getSourceAddressSet(), true);
		FunctionIterator dstFuncIter = dstProg.getFunctionManager().getFunctions(getDestinationAddressSet(), true);

		monitor.setIndeterminate(false);
		// TODO: The count is wrong, in case matches are excluded :/
		monitor.initialize(srcProg.getFunctionManager().getFunctionCount() + dstProg.getFunctionManager().getFunctionCount());
		
		monitor.setMessage("Bulking functions in " + srcProg.getName() + " [Source Program]");

		List<List<Long>> srcHashLists = new ArrayList<>();
		List<Address> srcAddrs = new ArrayList<>();
		List<List<Long>> dstHashLists = new ArrayList<>();
		List<Address> dstAddrs = new ArrayList<>();
		
		while (!monitor.isCancelled() && srcFuncIter.hasNext()) {
			monitor.incrementProgress(1);
			Function func = srcFuncIter.next();
			if (!func.isThunk()) {
				srcHashLists.add(bulker.hashes(func, monitor));
				srcAddrs.add(func.getEntryPoint());
			}
		}
		
		monitor.setMessage("Bulking functions in " + dstProg.getName() + " [Destination Program]");

		while (!monitor.isCancelled() && dstFuncIter.hasNext()) {
			monitor.incrementProgress(1);
			Function func = dstFuncIter.next();
			if (!func.isThunk()) {
				dstHashLists.add(bulker.hashes(func, monitor));
				dstAddrs.add(func.getEntryPoint());
			}
		}

		monitor.initialize(srcHashLists.size());
		monitor.setMessage("Matching...");
		
		for(int s=0; !monitor.isCancelled() && s<srcHashLists.size(); s++)
		{
			monitor.incrementProgress(1);
			for(int d=0; !monitor.isCancelled() && d<dstHashLists.size(); d++)
			{
				Address sourceAddress = srcAddrs.get(s);
				Address destinationAddress = dstAddrs.get(d);
				Function sourceFunction = getSourceProgram().getFunctionManager().getFunctionAt(sourceAddress);
				Function destinationFunction = getDestinationProgram().getFunctionManager().getFunctionAt(destinationAddress);

				double confidence_score = 10.0;
				if( ! sourceFunction.getName(true).equals(destinationFunction.getName(true)) )
				{
					confidence_score = 1.0;
					if( symbol_names_must_match )
						continue;
				}
				if( confidence_score < confidence_threshold )
				{
						continue;
				}
				
				double similarity_score = getBulkSimilarity(srcHashLists.get(s),dstHashLists.get(d));
				if( similarity_score < similarity_threshold )
				{
					continue;
				}
				
				VTScore similarity = new VTScore(similarity_score);
				VTScore confidence = new VTScore(confidence_score);
				
				int sourceLength = (int) sourceFunction.getBody().getNumAddresses();
				int destinationLength = (int) destinationFunction.getBody().getNumAddresses();
				
				matchInfo.setSimilarityScore(similarity);
				matchInfo.setConfidenceScore(confidence);
				matchInfo.setSourceLength(sourceLength);
				matchInfo.setDestinationLength(destinationLength);
				matchInfo.setSourceAddress(sourceAddress);
				matchInfo.setDestinationAddress(destinationAddress);
				matchInfo.setTag(null);
				matchInfo.setAssociationType(VTAssociationType.FUNCTION);
					
				matchSet.addMatch(matchInfo);
			}
		}
	}

	private double getBulkSimilarity(List<Long> srcList, List<Long> dstList) {
		Collections.sort(srcList);
		Collections.sort(dstList);
		int total = srcList.size() + dstList.size();
		int common = 0;
		int d = 0;
		int s = 0;
		while( s<srcList.size() && d<dstList.size() )
		{
			int c = srcList.get(s).compareTo(dstList.get(d));
			if( c>0 )
			{
				s++;
			}
			else if( c<0 )
			{
				d++;
			}
			else // c==0 
			{
				common++;
				s++;
				d++;
			}
		}
		
		return 2.0*((double)common/(double)total);
	}

}


