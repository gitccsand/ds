package com.tcp.testService;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Method;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;


public class RPCConsumer {
		
	public void consume(String serverIp,int PORT,String arg) throws NoSuchMethodException, SecurityException, UnknownHostException, IOException, ClassNotFoundException{
		//接口名称
				String interfacename = SayHelloSrv.class.getName();
				
				//需要远程执行的方法
				Method method = SayHelloSrv.class.getMethod("sayHello", java.lang.String.class);
				
				//需要传递到远端的参数
				Object[] arguments = {arg};
				
				Socket socket = new Socket(serverIp,PORT);
				
				//将方法名称和参数传递到远端
				ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
				output.writeUTF(interfacename);
				output.writeUTF(method.getName());
				output.writeObject(method.getParameterTypes());
				output.writeObject(arguments);
				
				//从远端读取方法执行结果
				ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
				Object result = input.readObject();
				
				System.out.println(result);
				
	}
	
	public static void main(String[] args) throws UnknownHostException,IOException,SecurityException, NoSuchMethodException, ClassNotFoundException {
		RPCConsumer consumer = new RPCConsumer();
		consumer.consume("127.0.0.1", 5678, "hello");
	}
}
