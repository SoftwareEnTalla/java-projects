package cu.entalla.app;

import cu.entalla.loader.Wso2PostConfigLoader;

public class Main {
    static public void main(String [] args){
        String file="/media/datos/Instaladores/entalla/tomcat/shared/classes/alfresco-global.properties";
        Wso2PostConfigLoader loader=new Wso2PostConfigLoader(file);
        loader.load();
        loader.getBeansLoaded();
        System.out.println("Ok");
    }
}
