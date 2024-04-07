package ServidorCliente;

import mp9.uf1.cryptoutils.MyCryptoUtils;

import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Cliente {
    public static void main(String[] args) {
        try {
            Socket socket = new Socket("localhost", 12345);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            KeyPair clientKeyPair = MyCryptoUtils.randomGenerate(2048);
            PublicKey clientPublicKey = clientKeyPair.getPublic();
            PrivateKey clientPrivateKey = clientKeyPair.getPrivate();

            out.writeObject(clientPublicKey);

            PublicKey serverPublicKey = (PublicKey) in.readObject();

            Thread readThread = new Thread(() -> {
                try {
                    while (true) {
                        byte[] encryptedData = (byte[]) in.readObject();

                        byte[] decryptedData = MyCryptoUtils.decryptData(encryptedData, clientPrivateKey);
                        System.out.println("Mensaje de Servidor: " + new String(decryptedData));
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
                        System.out.print("Cliente: ");
                        String msg = reader.readLine();

                        byte[] encryptedData = MyCryptoUtils.encryptData(msg.getBytes(), serverPublicKey);
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