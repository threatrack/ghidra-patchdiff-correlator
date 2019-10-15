/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package patchdiffcorrelator;

import ghidra.feature.vt.api.main.VTProgramCorrelatorAddressRestrictionPreference;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.util.HelpLocation;

public abstract class AbstractColorProgramCorrelatorFactory extends VTAbstractProgramCorrelatorFactory {
	
	public static final String ONLY_COLOR_BULK_MATCHED = "Dummy";
	public static final String ONLY_COLOR_BULK_MATCHED_DESC = "This is a dummy option, because Ghidra requires at least one option.";
	public static final boolean ONLY_COLOR_BULK_MATCHED_DEFAULT = false;

	private static final String helpLocationTopic = "patchdiffcorrelator";
	protected String helpLocationAnchor = "PatchDiffCorrelator";

	public AbstractColorProgramCorrelatorFactory() {
		super(VTProgramCorrelatorAddressRestrictionPreference.RESTRICTION_NOT_ALLOWED);
	}
	
	@Override
	public int getPriority() {
		return 10000; // run after all other correlators
	}
	
	@Override
	public VTOptions createDefaultOptions() {
		VTOptions options = new VTOptions(getName());
		HelpLocation help = new HelpLocation(helpLocationTopic, helpLocationAnchor);
		options.setOptionsHelpLocation(help);
		options.registerOption(ONLY_COLOR_BULK_MATCHED, ONLY_COLOR_BULK_MATCHED_DEFAULT, help, ONLY_COLOR_BULK_MATCHED_DESC);
		options.setBoolean(ONLY_COLOR_BULK_MATCHED, ONLY_COLOR_BULK_MATCHED_DEFAULT);
		return options;
	}

}
