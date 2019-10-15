package patchdiffcorrelator;

import java.awt.Color;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import generic.stl.Pair;
import ghidra.app.plugin.core.colorizer.ColorizingService;
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

public class BasicBlockMnemonicFunctionColorer extends AbstractFunctionColorer {
	public static final BasicBlockMnemonicFunctionColorer INSTANCE = new BasicBlockMnemonicFunctionColorer();
	
	@Override
	public void run(ColorizingService colorService, Function srcFunc, Function dstFunc, TaskMonitor monitor) throws CancelledException {
		List<Pair<Long,AddressSetView>> srcList = hashes(srcFunc, monitor);
		List<Pair<Long,AddressSetView>> dstList = hashes(dstFunc, monitor);
		int s = 0;
		int d = 0;
		while( s<srcList.size() && d<dstList.size() )
		{
			Pair<Long,AddressSetView> src = srcList.get(s);
			Pair<Long,AddressSetView> dst = dstList.get(d);
			// TOOO: FIXME: this breaks on duplicate basic blocks
			int c = src.first.compareTo(dst.first);
//			dstFunc.getProgram().getListing().setComment(dst.second.getMinAddress(), CodeUnit.EOL_COMMENT, "Coloring Correlator was here.");
			if( c<0 )
			{
//				srcFunc.getProgram().getListing().setComment(src.second.getMinAddress(), CodeUnit.PLATE_COMMENT, "Basic Block Differenece");
				//colorService.setBackgroundColor(src.second, new Color(200,160,160));
				s++;
			}
			else if( c>0 )
			{
//				dstFunc.getProgram().getListing().setComment(dst.second.getMinAddress(), CodeUnit.PLATE_COMMENT, "Basic Block Differenece");
				//colorService.setBackgroundColor(dst.second, new Color(200,160,160));
				d++;
			}
			else // c==0 
			{
				s++;
				d++;
			}
		}
		while( s<srcList.size() )
		{
			Pair<Long,AddressSetView> src = srcList.get(s);
//			srcFunc.getProgram().getListing().setComment(src.second.getMinAddress(), CodeUnit.PLATE_COMMENT, "Basic Block Differenece");
			//colorService.setBackgroundColor(src.second, new Color(200,160,160));
			s++;
		}
		while( d<dstList.size() )
		{
			Pair<Long,AddressSetView> dst = dstList.get(s);
//			dstFunc.getProgram().getListing().setComment(dst.second.getMinAddress(), CodeUnit.PLATE_COMMENT, "Basic Block Differenece");
			//colorService.setBackgroundColor(dst.second, new Color(200,160,160));
			d++;
		}
	}
	
	private List<Pair<Long,AddressSetView>> hashes(Function func, TaskMonitor monitor) throws CancelledException {
		List<Pair<Long,AddressSetView>> bbhashes = new ArrayList<>();
		
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

