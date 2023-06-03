package org.example.nativesummary.flowdroidbridge;

import java.util.LinkedList;
import java.util.List;

import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.config.SootConfigForAndroid;
import soot.options.Options;

public class SootConfig extends SootConfigForAndroid {
    @Override
	public void setSootOptions(Options options, InfoflowConfiguration config) {
        		// explicitly include packages for shorter runtime:
		List<String> excludeList = new LinkedList<String>();
		excludeList.add("java.*");
		excludeList.add("sun.*");

		// exclude classes of android.* will cause layout class cannot be
		// loaded for layout file based callback analysis.

		// 2020-07-26 (SA): added back the exclusion, because removing it breaks
		// calls to Android SDK stubs. We need a proper test case for the layout
		// file issue and then see how to deal with it.
		excludeList.add("android.*");

		excludeList.add("org.apache.*");
		excludeList.add("org.eclipse.*");
		excludeList.add("soot.*");
		excludeList.add("javax.*");
		options.set_exclude(excludeList);
		Options.v().set_no_bodies_for_excluded(true);
        // Options.v().set_prepend_classpath(true);
        Options.v().set_src_prec(Options.src_prec_apk);

        // super.setSootOptions(options, config);
        // TODO fix
        // String apk_path = Options.v().process_dir().get(0);
        // String sematicSummaryPath = apk_path.replaceFirst("\\.apk", "_ss.json");
		// new PreLoadAnalysis(sematicSummaryPath).do_analysis();
        // BodyBuilder.loadRequiredClasses();
    }

}
