package com.ciphertrust

import com.morpheusdata.core.MorpheusContext
import com.morpheusdata.cypher.Cypher;
import com.morpheusdata.cypher.CypherMeta;
import com.morpheusdata.cypher.CypherModule;
import com.morpheusdata.cypher.CypherObject
import com.morpheusdata.core.util.HttpApiClient
import com.morpheusdata.response.ServiceResponse
import groovy.util.logging.Slf4j;
import com.morpheusdata.core.Plugin;
import groovy.json.JsonOutput

@Slf4j
class ThalesCipherTrustCypherModule implements CypherModule {

    Cypher cypher;
    Plugin plugin;
    MorpheusContext morpheusContext
    @Override
    public void setCypher(Cypher cypher) {
        this.cypher = cypher;
    }
    
    public void setPlugin(Plugin plugin) {
      this.plugin = plugin
    }

    public void setMorpheusContext(MorpheusContext morpheusContext) {
        this.morpheusContext = morpheusContext
    }

    @Override
    public CypherObject write(String relativeKey, String path, String value, Long leaseTimeout, String leaseObjectRef, String createdBy) {
/*
        if(value != null && value.length() > 0) {
            String key = relativeKey;
            if(path != null) {
                key = path + "/" + key;
            }
            if(relativeKey.startsWith("config/")) {
                System.out.println("Writing to : " + key);
                return new CypherObject(key,value,0l, leaseObjectRef, createdBy);
            } else {
                String conjurUrl = plugin.getUrl();
                String conjurUsername = plugin.getUsername();
                String conjurApiKey = plugin.getApiKey();
                String conjurOrg = plugin.getOrganization();
                String conjurToken = getAuthToken(conjurUrl,conjurOrg,conjurUsername,conjurApiKey)
                //we gotta fetch from conjur
                String conjurPath="/secrets/${conjurOrg}/variable/" + relativeKey

                HttpApiClient apiClient = new HttpApiClient()
                apiClient.networkProxy = morpheusContext.services.setting.getGlobalNetworkProxy()
                def requestOpts = new HttpApiClient.RequestOptions(headers: ['Authorization': conjurToken], body: value)

                try {
                    ServiceResponse resp = apiClient.callApi(conjurUrl,conjurPath,null,null,requestOpts,"POST");
                    if(resp.getSuccess()) {
                        return new CypherObject(key,value,leaseTimeout, leaseObjectRef, createdBy);
                    } else {
                        return null;
                    }
                } catch(Exception ex) {
                    return null;
                }
            }

        } else {
            return null; //we dont write no value to a key
        }
*/
    }

    @Override
    public CypherObject read(String relativeKey, String path, Long leaseTimeout, String leaseObjectRef, String createdBy) {
/*
        String key = relativeKey;
        if(path != null) {
            key = path + "/" + key;
        }
        if(relativeKey.startsWith("config/")) {
            return null;
        } else {
            String conjurUrl = plugin.getUrl();
            String conjurUsername = plugin.getUsername();
            String conjurApiKey = plugin.getApiKey();
            String conjurOrg = plugin.getOrganization();
            String conjurToken = getAuthToken(conjurUrl,conjurOrg,conjurUsername,conjurApiKey)
            //we gotta fetch from conjur
            String conjurPath="/secrets/${conjurOrg}/variable/" + relativeKey
            HttpApiClient apiClient = new HttpApiClient()
            apiClient.networkProxy = morpheusContext.services.setting.getGlobalNetworkProxy()
            def requestOpts = new HttpApiClient.RequestOptions(headers: ['Authorization': conjurToken])
            try {
                ServiceResponse resp = apiClient.callApi(conjurUrl,conjurPath,null,null,requestOpts,"GET");
                if(resp.getSuccess()) {
                    ObjectMapper mapper = new ObjectMapper();

                    CypherObject conjurResult = new CypherObject(key,resp.getContent(),leaseTimeout,leaseObjectRef, createdBy);
                    conjurResult.shouldPersist = false;
                    return conjurResult;
                } else {
                    log.error("Error Fetching cypher key: ${resp}")
                    return null;//throw exception?
                }
            } catch(Exception ex) {
                log.error("Error Occurred reading conjur key {}",ex.message,ex)
                return null;
            }

        }
*/
    }

    @Override
    public boolean delete(String relativeKey, String path, CypherObject object) {
/*
        if(relativeKey.startsWith("config/")) {
            return true;
        } else {
            String conjurUrl = plugin.getUrl();
            String conjurUsername = plugin.getUsername();
            String conjurApiKey = plugin.getApiKey();
            String conjurOrg = plugin.getOrganization();
            boolean clearSecretOnDeletion = plugin.getClearSecretOnDeletion();
            if(clearSecretOnDeletion) {
              String conjurToken = getAuthToken(conjurUrl,conjurOrg,conjurUsername,conjurApiKey)
              //we gotta fetch from conjur
              String conjurPath="/secrets/${conjurOrg}/variable/" + relativeKey
              HttpApiClient apiClient = new HttpApiClient()
              apiClient.networkProxy = morpheusContext.services.setting.getGlobalNetworkProxy()
              def requestOpts = new HttpApiClient.RequestOptions(headers: ['Authorization': conjurToken], body: JsonOutput.toJson(""))
              try {
                  apiClient.callApi(conjurUrl,conjurPath,null,null,requestOpts,"POST");
              } catch(Exception ex) {

              }
            }
            return true;
        }
    }

    protected getAuthToken(String conjurUrl, String conjurOrg, String conjurUsername, String conjurApiKey) {
        HttpApiClient apiClient = new HttpApiClient()
        apiClient.networkProxy = morpheusContext.services.setting.getGlobalNetworkProxy()
        def requestOpts = new HttpApiClient.RequestOptions(headers: ['Accept-Encoding':'base64'], body: conjurApiKey)
        //Conjur usernames frequently require URL encoded / in the path. For example host%2Fapp
        //HttpApiClient uses apache URLBuilder which will double encode unless we are careful.
        def url = "${conjurUrl}/authn/${URLEncoder.encode(conjurOrg, 'UTF-8')}/${URLEncoder.encode(conjurUsername, 'UTF-8')}/authenticate"
        ServiceResponse resp = apiClient.callApi(url,null,null,null,requestOpts,"POST");
        if(resp.getSuccess()) {
            return "Token token=\"${resp.getContent()}\""
        } else {
            return null;//throw exception?
        }
*/

    }


    @Override
    public String getUsage() {
        StringBuilder usage = new StringBuilder();

        usage.append("This allows secret data to be fetched from a Thales Ciphertrust integration. This can be configured in the plugin integration settings.");

        return usage.toString();
    }

    @Override
    public String getHTMLUsage() {
        return null;
    }

    /**
     * The readFromDatastore method is used to determine if Cypher should read from the value stored within the {@link Datastore} on read requests
     * @return if this returns false then Cypher read requests are always executed through the module and do not read from a value that exists within the {@link Datastore}.
     */
    @Override
    Boolean readFromDatastore() {
        return false //important to ensure reads are always obtained from ciphertrust
    }
}
