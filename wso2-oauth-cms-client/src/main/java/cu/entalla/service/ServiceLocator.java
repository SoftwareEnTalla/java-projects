package cu.entalla.service;

import cu.entalla.udi.ClientServiceIntegration;

public class ServiceLocator {
    private static ClientServiceIntegration Integrator;

    public static void registerIntegrator(ClientServiceIntegration integration) {
        Integrator = integration;
    }
    public static ClientServiceIntegration getIntegrator() {
        if (Integrator == null) {
            throw new IllegalStateException("No ClientServiceIntegration implementation registered!");
        }
        return Integrator;
    }

}
