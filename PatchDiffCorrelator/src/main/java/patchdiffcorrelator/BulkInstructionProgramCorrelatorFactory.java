package patchdiffcorrelator;

import ghidra.feature.vt.api.main.VTProgramCorrelator;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

public class BulkInstructionProgramCorrelatorFactory extends AbstractBulkProgramCorrelatorFactory {
	static final String DESC = "Compares functions based on their included instructions without taking the order of the instructions into account.";
	static final String NAME = "Bulk Instructions Match";
	
	@Override
	protected VTProgramCorrelator doCreateCorrelator(ServiceProvider serviceProvider,
			Program sourceProgram, AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, VTOptions options) {
		return new BulkProgramCorrelator(serviceProvider, sourceProgram, sourceAddressSet,
			destinationProgram, destinationAddressSet, options, NAME, InstructionFunctionBulker.INSTANCE);
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
