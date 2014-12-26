package com.tcp.testService;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

public class RPCProvider {
	
	//所有的服务
	protected static Map<String, Object> services = new HashMap<String, Object>();
	
	static{
		services.put(SayHelloSrv.class.getName(),new SayHelloSrvImpl());
	}
	
	public void provide(int PORT) throws ClassNotFoundException, NoSuchMethodException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, IOException{
		ServerSocket server = new ServerSocket(PORT);
		System.out.println("Service sayHello started at port "+ PORT);
		
		while(true){
			Socket socket = server.accept();
			//读取服务信息
			ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			String interfacename = input.readUTF();
			String methodname = input.readUTF();
			Class<?>[] parameterTypes = (Class<?>[])input.readObject();
			Object[] arguments = (Object[])input.readObject();
			
			//执行调用
			Class serviceinterfaceclass = Class.forName(interfacename);
			Object service = services.get(interfacename);
			Method method = serviceinterfaceclass.getMethod(methodname, parameterTypes);
			Object result = method.invoke(service, arguments);
			
			
			ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			output.writeObject(result);
		}
	}


	public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchMethodException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		RPCProvider provider = new RPCProvider();
		provider.provide(5678);

	}

}
