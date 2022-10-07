package analysis.exercise1;

import analysis.AbstractAnalysis;
import analysis.VulnerabilityReporter;
import soot.*;
import soot.jimple.*;

public class MisuseAnalysis extends AbstractAnalysis{
	public MisuseAnalysis(Body body, VulnerabilityReporter reporter) {
		super(body, reporter);
	}
	
	@Override
	protected void flowThrough(Unit unit) {
		String invClassName = "javax.crypto.Cipher";
		String invMethodName = "getInstance";
		Stmt st = (Stmt) unit; // cast to statement
		if (st.containsInvokeExpr()) { // check if the statement contains an invoke expression
			InvokeExpr invExpr = st.getInvokeExpr(); // retrieves the invoke expression
			SootMethod invMeth = invExpr.getMethod();
			SootClass invDeclClass = invExpr.getMethod().getDeclaringClass();
			if (invMeth.getName().equals(invMethodName) && invDeclClass.getName().equals(invClassName)) {
				Value arg = invExpr.getArg(0);
				if (arg instanceof StringConstant) {
					StringConstant constant = (StringConstant) arg;
					if (!constant.value.equals("AES/GCM/PKCS5Padding"))
						reporter.reportVulnerability(method.getSignature(), unit);
				}
			}
		}
	}
}
