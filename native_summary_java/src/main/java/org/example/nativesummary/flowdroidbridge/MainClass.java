package org.example.nativesummary.flowdroidbridge;

import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;

public class MainClass extends soot.jimple.infoflow.cmd.MainClass {

	

    @Override
	/**
	 * Creates an instance of the FlowDroid data flow solver tool for Android.
	 * Derived classes can override this method to inject custom variants of
	 * FlowDroid.
	 * 
	 * @param config The configuration object
	 * @return An instance of the data flow solver
	 */
	protected SetupApplication createFlowDroidInstance(final InfoflowAndroidConfiguration config) {
		SetupApplication ret = new SetupApplication(config);
		ret.setSootConfig(new SootConfig());
		return ret;
	}

	public static void main(String[] args) throws Exception {
		MainClass main = new MainClass();
		main.run(args);
	}
}
