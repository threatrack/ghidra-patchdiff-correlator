package patchdiffcorrelator;

import ghidra.feature.vt.api.main.VTProgramCorrelator;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

public abstract class ColorBasicBlockMnemonicProgramCorrelatorFactory extends AbstractColorProgramCorrelatorFactory {
	static final String NAME = "Coloring Basic Block Mnemonics";
	static final String DESC = "Color the changed basic blocks in the source and destination programs.";
	
	@Override
	protected VTProgramCorrelator doCreateCorrelator(ServiceProvider serviceProvider,
			Program sourceProgram, AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, VTOptions options) {
		return new ColorProgramCorrelator(serviceProvider, sourceProgram, sourceAddressSet,
			destinationProgram, destinationAddressSet, options, NAME, BasicBlockMnemonicFunctionColorer.INSTANCE);
	}
	
	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public String getDescription() {
		return DESC;
	}
}
