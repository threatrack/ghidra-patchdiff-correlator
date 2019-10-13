package patchdiffcorrelator;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import generic.stl.Pair;

import static patchdiffcorrelator.BulkProgramCorrelatorFactory.*;

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
		boolean ignore_undefined = getOptions().getBoolean(IGNORE_UNDEFINED_SYMBOLS, IGNORE_UNDEFINED_SYMBOLS_DEFAULT);
		boolean only_match_accepted = getOptions().getBoolean(ONLY_MATCH_ACCEPTED_MATCHES, ONLY_MATCH_ACCEPTED_MATCHES_DEFAULT);

		VTMatchInfo matchInfo = new VTMatchInfo(matchSet);
		
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
		if( only_match_accepted )
		{
			final VTSession session = matchSet.getSession();
			List<VTMatchSet> matchSets = session.getMatchSets();

			monitor.initialize(matchSets.size());
			monitor.setMessage("(2/3) Calculating diff set (from accepted matches)");

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
						if( ms.getProgramCorrelatorInfo().getName().equals(name) )
						{
							// don't add another match if a match already exists
							diffSet.remove(addr);
						}
						else
						{
							diffSet.add(addr);
						}
					}
				}
			}
		}
		else
		{
			monitor.initialize(srcHashMap.size() * dstHashMap.size());
			monitor.setMessage("(2/3) Calculating diff set (from all functions)");
			// compare every source with every destination function
			for(Address s : srcHashMap.keySet())
			{
				monitor.checkCanceled();
				monitor.incrementProgress(1);
				for(Address d : dstHashMap.keySet())
				{
					monitor.checkCanceled();
					monitor.incrementProgress(1);
					Pair<Address,Address> addr = new Pair<Address,Address>(s, d);
					diffSet.add(addr);
				}
			}
		}

		monitor.initialize(diffSet.size());
		monitor.setMessage("(3/3) Matching...");
		
		for(Pair <Address,Address> addr : diffSet)
		{
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			Function srcFunc = getSourceProgram().getFunctionManager().getFunctionAt(addr.first);
			Function dstFunc = getDestinationProgram().getFunctionManager().getFunctionAt(addr.second);

			if( symbol_names_must_match && ignore_undefined )
			{
				// TODO: do this proper: https://github.com/NationalSecurityAgency/ghidra/blob/49c2010b63b56c8f20845f3970fedd95d003b1e9/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/prototype/match/MatchSymbol.java#L152
				if( srcFunc.getName().startsWith("FUN_") )
				{
					continue;
				}
			}
			double confidence_score = 10.0;
			if( ! srcFunc.getName(true).equals(dstFunc.getName(true)) )
			{
				confidence_score = 1.0;
				if( symbol_names_must_match )
				{
					continue;
				}
			}
			if( confidence_score < confidence_threshold )
			{
					continue;
			}

			if(srcHashMap.get(addr.first)==null)
			{
				srcHashMap.replace(addr.first, bulker.hashes(srcFunc, monitor));
			}
			if(dstHashMap.get(addr.second)==null)
			{
				dstHashMap.replace(addr.second, bulker.hashes(dstFunc, monitor));
			}
			
			double similarity_score = getBulkSimilarity(srcHashMap.get(addr.first),dstHashMap.get(addr.second));
			if( similarity_score < similarity_threshold )
			{
				continue;
			}
			
			VTScore similarity = new VTScore(similarity_score);
			VTScore confidence = new VTScore(confidence_score);
			
			int sourceLength = (int) srcFunc.getBody().getNumAddresses();
			int destinationLength = (int) dstFunc.getBody().getNumAddresses();
			
			matchInfo.setSimilarityScore(similarity);
			matchInfo.setConfidenceScore(confidence);
			matchInfo.setSourceLength(sourceLength);
			matchInfo.setDestinationLength(destinationLength);
			matchInfo.setSourceAddress(addr.first);
			matchInfo.setDestinationAddress(addr.second);
			matchInfo.setTag(null);
			matchInfo.setAssociationType(VTAssociationType.FUNCTION);
				
			matchSet.addMatch(matchInfo);
		}
	}

	private double getBulkSimilarity(List<Long> srcList, List<Long> dstList) {
		Collections.sort(srcList);
		Collections.sort(dstList);
		int total = Integer.max(srcList.size(),dstList.size());
		int common = 0;
		int d = 0;
		int s = 0;
		// TODO: this is unbelievable slow
		while( s<srcList.size() && d<dstList.size() )
		{
			int c = srcList.get(s).compareTo(dstList.get(d));
			if( c<0 )
			{
				s++;
			}
			else if( c>0 )
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
		return (double)common/(double)total;
	}
	
}


