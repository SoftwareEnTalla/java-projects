package cu.entalla.handlers;

import cu.entalla.udi.EventHandler;

public class TokenExpirationHandler implements Runnable {

    private final EventHandler tokenResponse;

    public TokenExpirationHandler(EventHandler tokenResponse) {
        this.tokenResponse = tokenResponse;
    }

    @Override
    public void run() {
        synchronized (tokenResponse) {
            try {
                // El hilo se pone en espera hasta que el token expire
                System.out.println(Thread.currentThread().getName() + " está esperando la expiración del token.");
                tokenResponse.wait();  // Espera la notificación de expiración del token
                onTokenExpired();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private void onTokenExpired() {
        // Aquí puedes agregar la lógica que deseas ejecutar cuando el token haya expirado
        System.out.println(Thread.currentThread().getName() + " ha recibido la notificación de expiración del token.");
        // Ejemplo: renovar el token, o realizar alguna tarea en tu sistema.
    }
}
