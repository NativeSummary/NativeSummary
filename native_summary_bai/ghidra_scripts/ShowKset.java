//TODO write a description for this script
//@author
//@category _NativeSummary
//@keybinding
//@menupath
//@toolbar

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.util.GlobalState;
import com.bai.util.Logging;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import org.javimmutable.collections.JImmutableMap;

public class ShowKset extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Address startAddr = currentLocation.getAddress();
		Function fu = GlobalState.flatAPI.getFunctionContaining(startAddr);
		for (Context context : Context.getContext(fu)) {
			AbsEnv absEnv = context.getAbsEnvIn().get(startAddr);
			Logging.info("Context: "+context.toString());
			StringBuilder stringBuilder = new StringBuilder();
			for (JImmutableMap.Entry<ALoc, KSet> entry : absEnv.getEnvMap()) {
				ALoc aLoc = entry.getKey();
				KSet kSet = entry.getValue();
				if (aLoc.getRegion().isReg()) {
					absEnv.writeRegEntry(stringBuilder, aLoc, kSet);
				}
			}
			Logging.info("  AbsEnv: "+ stringBuilder);
		}
	}
}
