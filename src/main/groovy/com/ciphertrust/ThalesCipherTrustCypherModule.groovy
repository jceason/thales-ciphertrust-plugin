package com.ciphertrust

import com.morpheusdata.core.providers.CypherModuleProvider
import com.morpheusdata.core.MorpheusContext
import com.morpheusdata.core.Plugin
import com.morpheusdata.core.util.HttpApiClient
import com.morpheusdata.model.AccountCredential
import com.morpheusdata.model.AccountIntegration
import com.morpheusdata.cypher.Cypher;
import com.morpheusdata.cypher.CypherMeta;
import com.morpheusdata.cypher.CypherModule;
import com.morpheusdata.cypher.CypherObject

import com.morpheusdata.model.OptionType
import com.morpheusdata.response.ServiceResponse
import groovy.json.JsonSlurper
import groovy.json.JsonOutput
import groovy.util.logging.Slf4j



@Slf4j
class ThalesCipherTrustCypherModule implements CypherModule {

    Cypher cypher;
    Plugin plugin;
    String jwtToken;
    long timeJWT

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

        HttpApiClient apiClient = new HttpApiClient()

        apiClient.networkProxy = morpheusContext.services.setting.getGlobalNetworkProxy()
        String apiUrl = plugin.getUrl();
        String username = plugin.getServiceUsername();
        String password = plugin.getServicePassword();
        String domain = plugin.getDomain();

        try {
            def authResults = authToken(apiUrl,username,password,domain)
            log.info("write cypher back from authToken")
            if(authResults.success) {

                //HttpApiClient apiClient = new HttpApiClient()
                apiClient.networkProxy = morpheusContext.services.setting.getGlobalNetworkProxy()\
/*
                def headers = ['Accept': 'application/json' , 'Content-Type':'application/json']
                def body = ['grant_type':'password' , 'domain':domain , 'username':username , 'password':password ]

                HttpApiClient.RequestOptions restOptions = new HttpApiClient.RequestOptions([headers:headers , body:body])
                log.info("header is  ${headers}")
                log.info("body is  ${body}")

                log.info("Calling endpoint  ${apiUrl}v1/vault/keys2")
                def apiResults = apiClient.callApi(apiUrl,'v1/vault/keys2',null,null,restOptions,'POST')
*/

            } else {
                return ServiceResponse.error(authResults.error)
            }
        } catch (Exception exception) {
            log.error("write cypher unable to create cypher", exception)
            return null
        }
        finally {
            apiClient.shutdownClient()
        }

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

   */
    }


    protected ServiceResponse<Map> authToken(String apiUrl, String username, String password, String domain) {
        long currentTime = System.currentTimeMillis() / 1000

        //give a cushion of 10 seconds
        if(this.timeJWT > (currentTime + 10)) {
            return  ServiceResponse.success("Credentials auth token still valid")
        }

        HttpApiClient apiClient = new HttpApiClient()
        apiClient.networkProxy = morpheusContext.services.setting.getGlobalNetworkProxy()\

        def headers = ['Accept': 'application/json' , 'Content-Type':'application/json']
        def body = ['grant_type':'password' , 'domain':domain , 'username':username , 'password':password ]

        HttpApiClient.RequestOptions restOptions = new HttpApiClient.RequestOptions([headers:headers , body:body])
        log.info("header is  ${headers}")
        log.info("body is  ${body}")

        try {
            log.info("Calling endpoint  ${apiUrl}v1/auth/tokens")
            def apiResults = apiClient.callApi(apiUrl,'v1/auth/tokens',null,null,restOptions,'POST')
            log.info("apiresults is  ${apiResults}")

            if(apiResults.success) {
                def jsonSlurper = new JsonSlurper()
                def resultContent = jsonSlurper.parseText (apiResults.content.toString())
                log.info("Successfully retrieved a new jwt  ${resultContent.jwt}")
                this.jwtToken = resultContent.jwt
                //default expire in 300 seconds
                this.timeJWT = (System.currentTimeMillis() / 1000) + 300

                return  ServiceResponse.success("Successfully retrieve jwt from authToken")

            } else {
                log.info("Failed to retrieve a new jwt token ")
                return ServiceResponse.error(apiResults.error ?: apiResults.content ?: "An unknown error occurred authenticating CipherTrust")
            }
        }  finally {
            apiClient.shutdownClient()
        }

    }


    @Override
    public String getUsage() {
        StringBuilder usage = new StringBuilder();

        usage.append("This allows cyphers to be fetched from a Thales CipherTrust integration. This can be configured in the plugin integration settings.");

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
