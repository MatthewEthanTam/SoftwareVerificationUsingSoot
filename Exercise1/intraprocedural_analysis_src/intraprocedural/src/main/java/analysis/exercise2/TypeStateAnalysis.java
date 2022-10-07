package analysis.exercise2;

import java.util.Set;

import analysis.FileStateFact;
import analysis.ForwardAnalysis;
import analysis.VulnerabilityReporter;
import soot.Body;
import soot.Unit;

public class TypeStateAnalysis extends ForwardAnalysis<Set<FileStateFact>> {

	public TypeStateAnalysis(Body body, VulnerabilityReporter reporter) {
		super(body, reporter);
	}

	@Override
	protected void flowThrough(Set<FileStateFact> in, Unit unit, Set<FileStateFact> out) {
		copy(in, out);
		// TODO: Implement your flow function here.
		prettyPrint(in, unit, out);
	}

	@Override
	protected Set<FileStateFact> newInitialFlow() {
		// TODO: Implement your initialization here.
		return null;
	}

	@Override
	protected void copy(Set<FileStateFact> source, Set<FileStateFact> dest) {
		// TODO: Implement the copy function here.
	}

	@Override
	protected void merge(Set<FileStateFact> in1, Set<FileStateFact> in2, Set<FileStateFact> out) {
		// TODO: Implement the merge function here.
	}

}
