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
		String correctConvention = "AES/GCM/PKCS5Padding";
		Stmt st = (Stmt) unit;
		if (st.containsInvokeExpr()) { // check if the statement contains an invoke expression
			InvokeExpr invExpr = st.getInvokeExpr(); 
			SootMethod invMeth = invExpr.getMethod(); 
			SootClass invDeclClass = invExpr.getMethod().getDeclaringClass(); 
			String invName = invMeth.getName();
			String invDeclName = invDeclClass.getName();
			if (invName.equals(invMethodName) && invDeclName.equals(invClassName)) {  // check if the invoke expression is a call to Cipher.getInstance
				if (invExpr.getArg(0) instanceof StringConstant) { // check if the argument is a string constant
					StringConstant constant = (StringConstant) invExpr.getArg(0); 
					if (!constant.value.equals(correctConvention)) {
						reporter.reportVulnerability(method.getSignature(), unit);
					}
				}
			}
		}
	}
}
