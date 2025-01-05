package cu.entalla.model;


import org.alfresco.service.namespace.NamespaceException;
import org.alfresco.service.namespace.NamespaceService;
import org.alfresco.util.OneToManyHashBiMap;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

public class AutoConfigureNamespaceServiceMemoryImpl implements NamespaceService {

    private static final Logger logger = Logger.getLogger(AutoConfigureNamespaceServiceMemoryImpl.class.getName());

    private List<String> allPrefixes=new ArrayList<>();
    private List<String> allUris=new ArrayList<>();
    public AutoConfigureNamespaceServiceMemoryImpl() {
        super();
        allPrefixes=new ArrayList<>();
        allUris=new ArrayList<>();
        registerDefaultNamespaces();
    }

    private AutoConfigureNamespaceServiceMemoryImpl registerDefaultNamespaces() {
        logger.info("Comenzando a registrar namespaces");
        // Lista de prefijos y URIs para namespaces
        Map<String, String> defaultNamespaces = Map.ofEntries(
                Map.entry(NamespaceService.DEFAULT_PREFIX, NamespaceService.DEFAULT_URI),
                Map.entry(NamespaceService.ALFRESCO_PREFIX, NamespaceService.ALFRESCO_URI),
                Map.entry(NamespaceService.DICTIONARY_MODEL_PREFIX, NamespaceService.DICTIONARY_MODEL_1_0_URI),
                Map.entry(NamespaceService.SYSTEM_MODEL_PREFIX, NamespaceService.SYSTEM_MODEL_1_0_URI),
                Map.entry(NamespaceService.CONTENT_MODEL_PREFIX, NamespaceService.CONTENT_MODEL_1_0_URI),
                Map.entry(NamespaceService.APP_MODEL_PREFIX, NamespaceService.APP_MODEL_1_0_URI),
                Map.entry(NamespaceService.AUDIO_MODEL_PREFIX, NamespaceService.AUDIO_MODEL_1_0_URI),
                Map.entry(NamespaceService.WEBDAV_MODEL_PREFIX, NamespaceService.WEBDAV_MODEL_1_0_URI),
                Map.entry(NamespaceService.EXIF_MODEL_PREFIX, NamespaceService.EXIF_MODEL_1_0_URI),
                Map.entry(NamespaceService.DATALIST_MODEL_PREFIX, NamespaceService.DATALIST_MODEL_1_0_URI),
                Map.entry(NamespaceService.BPM_MODEL_PREFIX, NamespaceService.BPM_MODEL_1_0_URI),
                Map.entry(NamespaceService.WORKFLOW_MODEL_PREFIX, NamespaceService.WORKFLOW_MODEL_1_0_URI),
                Map.entry(NamespaceService.FORUMS_MODEL_PREFIX, NamespaceService.FORUMS_MODEL_1_0_URI),
                Map.entry(NamespaceService.LINKS_MODEL_PREFIX, NamespaceService.LINKS_MODEL_1_0_URI),
                Map.entry(NamespaceService.RENDITION_MODEL_PREFIX, NamespaceService.RENDITION_MODEL_1_0_URI),
                Map.entry(NamespaceService.REPOSITORY_VIEW_PREFIX, NamespaceService.REPOSITORY_VIEW_1_0_URI),
                Map.entry(NamespaceService.SECURITY_MODEL_PREFIX, NamespaceService.SECURITY_MODEL_1_0_URI),
                Map.entry(NamespaceService.EMAILSERVER_MODEL_PREFIX, NamespaceService.EMAILSERVER_MODEL_URI)
        );

        // Registrar cada par
        defaultNamespaces.forEach((prefix, uri) -> {
            try {
                if(uri!=null && !uri.isEmpty() && prefix!=null && !prefix.isEmpty()){
                    // Trazas para depuración
                    logger.info("Attempting to register namespace:");
                    logger.info("Prefix: " + prefix + ", URI: " + uri);

                    // Registrar el namespace
                    addNamespace(prefix, uri);

                }
                else {
                    // Validar que el prefijo y la URI no sean nulos ni vacíos
                    if (prefix == null || prefix.isEmpty()) {
                        logger.warning("Skipped registering namespace: Prefix is null or empty.");
                        return;
                    }
                    if (uri == null || uri.isEmpty()) {
                        logger.warning("Skipped registering namespace: URI is null or empty for Prefix = " + prefix);
                        return;
                    }
                }

            } catch (Exception e) {
                // Manejo de errores
                logger.severe("Failed to register namespace: Prefix = " + prefix + ", URI = " + uri);
                logger.severe("Error: " + e.getMessage());
            }
        });
        return this;

    }

    // Método público para registrar namespaces adicionales
    public void addNamespace(String prefix, String uri) {
        boolean okPrefije = !allPrefixes.contains(prefix) ? allPrefixes.add(prefix) : true;
        boolean okUri = okPrefije && !allUris.contains(uri) ? allUris.add(uri) : true;
        // Confirmación de registro
        logger.info("Successfully registered namespace: Prefix = " + prefix+" => (" +okPrefije+"), URI = " + uri+" => ("+okUri+")");
        this.registerNamespace(prefix, uri);
    }
    private final OneToManyHashBiMap<String, String> map = new OneToManyHashBiMap();

    public void registerNamespace(String prefix, String uri) {

        this.map.putSingleValue(prefix,uri);
    }

    public void unregisterNamespace(String prefix) {
        this.map.removeValue(prefix);
    }

    public String getNamespaceURI(String prefix) throws NamespaceException {
        return (String)this.map.getKey(prefix);
    }

    public Collection<String> getPrefixes(String namespaceURI) throws NamespaceException {
        return  this.map.get(namespaceURI);
    }

    public AutoConfigureNamespaceServiceMemoryImpl clear(){
        map.clear();
        allPrefixes.clear();
        allUris.clear();
        return this;
    }
    public Collection<String> getPrefixes() {
        return allPrefixes;// this.map.keySet();
    }

    public Collection<String> getURIs() {
        return allUris;// this.map.flatValues();
    }
}