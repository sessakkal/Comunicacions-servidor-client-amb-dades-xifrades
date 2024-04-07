package ServidorCliente;

import mp9.uf1.cryptoutils.MyCryptoUtils;

import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.PublicKey;

public class Servidor {
    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(12345);
            System.out.println("Servidor esperando conexiones...");
            Socket socket = serverSocket.accept();
            System.out.println("Cliente conectado");

            KeyPair serverKeyPair = MyCryptoUtils.randomGenerate(2048);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            out.writeObject(serverKeyPair.getPublic());

            PublicKey clientPublicKey = (PublicKey) in.readObject();

            Thread readThread = new Thread(() -> {
                try {
                    while (true) {
                        byte[] encryptedData = (byte[]) in.readObject();

                        byte[] decryptedData = MyCryptoUtils.decryptData(encryptedData, serverKeyPair.getPrivate());
                        System.out.println("Mensaje de Cliente: " + new String(decryptedData));
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
            readThread.start();

            Thread writeThread = new Thread(() -> {
                try {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                    while (true) {
                        System.out.print("Servidor: ");
                        String msg = reader.readLine();

                        byte[] encryptedData = MyCryptoUtils.encryptData(msg.getBytes(), clientPublicKey);
                        out.writeObject(encryptedData);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
            writeThread.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}