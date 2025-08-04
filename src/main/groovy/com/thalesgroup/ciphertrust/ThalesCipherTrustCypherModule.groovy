package com.thalesgroup.ciphertrust

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
    public CypherObject write(String key, String path, String value, Long leaseTimeout, String leaseObjectRef, String createdBy) {

        HttpApiClient apiClient = new HttpApiClient()

        apiClient.networkProxy = morpheusContext.services.setting.getGlobalNetworkProxy()
        String apiUrl = plugin.getUrl();
        String username = plugin.getServiceUsername();
        String password = plugin.getServicePassword();
        String domain = plugin.getDomain();

        try {
            def authResults = authToken(apiUrl,username,password,domain)
            def body = ['']
            if(authResults.success) {
                String bearerString =    'Bearer ' + jwtToken
                String endpoint = 'v1/vault/keys2'

                if (key.startsWith "rotate/") {
                    log.debug("key rotation requested ${key}")
                    def parts  = key.split("/")
                    key = parts[1]
                    body = ['description':key]
                    endpoint = 'v1/vault/keys2/' + key + '/versions'
                } else {
                    def parts  = key.split("/")
                    // Possible algorithms
                    // aes tdes rsa ec hmac-sha1 hmac-sha256 hmac-sha384 hmac-sha512 seed aria opaque
                    String alg = parts[0]
                    key = parts[1]
                    body = ['name':key , 'algorithm':alg ]
                }
                def headers = ['Accept': 'application/json', 'Content-Type': 'application/json' , 'Authorization': bearerString ]


                HttpApiClient.RequestOptions restOptions = new HttpApiClient.RequestOptions([headers:headers , body:body])
                /*log.info("header is  ${headers}")
                log.info("body is  ${body}")
                log.info("key parm is  ${key}")
                log.info("path parm is  ${path}")
                log.info("Calling endpoint  ${endpoint}")

                 */

                def apiResults = apiClient.callApi(apiUrl,endpoint,null,null,restOptions,'POST')
                if(apiResults.getSuccess()) {

                    /*
                    log.info("Successfully created key ${key} " )
                    CypherObject keyResults = this.read( key,  path,  leaseTimeout,  leaseObjectRef,  createdBy)

                    log.info("Successfully created key  ${keyResults.key}")
                    log.info("Successfully created key value ${keyResults.value}")

                    log.info("Successfully created key leaseTimeout ${keyResults.leaseTimeout}")
                    log.info("Successfully created key leaseObjectRef :w${keyResults.leaseObjectRef}")
                    log.info("Successfully created key createdBy ${keyResults.createdBy}")
                    */

                    CypherObject rtn = new CypherObject(key,value,leaseTimeout,leaseObjectRef, createdBy);
                    //rtn.shouldPersist = false;
                    return rtn
                } else {
                    log.error("Cypher failed to write key ")
                    return null
                }

            } else {
                log.error("Cypher failed to write key ")
                return null
            }
        } catch (Exception exception) {
            log.error("Cypher failed to write key", exception)
            return null
        }
        finally {
            apiClient.shutdownClient()
        }

    }



    @Override
    public CypherObject read(String key, String path, Long leaseTimeout, String leaseObjectRef, String createdBy) {

        HttpApiClient apiClient = new HttpApiClient()

        apiClient.networkProxy = morpheusContext.services.setting.getGlobalNetworkProxy()
        String apiUrl = plugin.getUrl();
        String username = plugin.getServiceUsername();
        String password = plugin.getServicePassword();
        String domain = plugin.getDomain();

        try {
            def authResults = authToken(apiUrl, username, password, domain)

            if (authResults.success) {
                String bearerString =    'Bearer ' + jwtToken
                def headers = ['Accept': 'application/json', 'Content-Type': 'application/json' , 'Authorization': bearerString ]
                //def body = ['type': 'name']

                HttpApiClient.RequestOptions restOptions = new HttpApiClient.RequestOptions([headers: headers])
                /*log.info("header is  ${headers}")
                log.info("body is  ${body}")
                log.info("key is ${key}")
                log.info("path is  ${path}")
                 */
                String endPoint = 'v1/vault/keys2/' + key + '/export'
                //log.info("endPoint is ${endPoint}")

                def apiResults = apiClient.callApi(apiUrl,endPoint,null,null,restOptions,'POST')

                if(apiResults.getSuccess()) {
                    def jsonSlurper = new JsonSlurper()
                    def resultContent = jsonSlurper.parseText (apiResults.content.toString())

                    log.debug("Successfully retrieved key ${key}")
                    //log.info("Successfully retrieved key material ${resultContent.material}")

                    CypherObject keyResults = new CypherObject(key,resultContent.material,leaseTimeout,leaseObjectRef, createdBy);
                    keyResults.shouldPersist = false;
                    return keyResults;
                } else {
                    log.debug("Cypher failed to read key ")
                    return null
                }
            } else {
                log.error("Cypher failed to read key ")
                return null
            }
        } catch (Exception exception) {
            log.error("Cypher failed to read key ", exception)
            return null
        }
        finally {
            apiClient.shutdownClient()
        }
    }


    @Override
    public boolean delete(String key, String path, CypherObject object) {
        HttpApiClient apiClient = new HttpApiClient()

        apiClient.networkProxy = morpheusContext.services.setting.getGlobalNetworkProxy()
        String apiUrl = plugin.getUrl();
        String username = plugin.getServiceUsername();
        String password = plugin.getServicePassword();
        String domain = plugin.getDomain();

        try {
            def authResults = authToken(apiUrl, username, password, domain)
            log.info("delete cypher back from authToken")
            if (authResults.success) {
                String bearerString = 'Bearer ' + jwtToken

                def headers = ['Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': bearerString]

                HttpApiClient.RequestOptions restOptions = new HttpApiClient.RequestOptions([headers: headers])
                String endPoint = 'v1/vault/keys2/' + key
                log.info("Calling delete endpoint ${endPoint}")

                def apiResults = apiClient.callApi(apiUrl, endPoint, null, null, restOptions, 'DELETE')
                if (apiResults.getSuccess()) {
                    log.info("Successfully deleted key ${key} ")
                    return true
                } else {
                    log.error("Cypher failed to delete key ")
                    return false
                }
            } else {
                log.info("Cypher failed to delete key  ")
                return false
            }
        } catch (Exception exception) {
            log.error("Cypher failed to delete key", exception)
            return false
        }
        finally {
            apiClient.shutdownClient()
        }
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

                return  ServiceResponse.success("Successfully retrieve cypher token from authToken")

            } else {
                log.error("Failed to retrieve a new cypher token ")
                return ServiceResponse.error(apiResults.error ?: apiResults.content ?: "An unknown error occurred authenticating CipherTrust")
            }
        } catch (Exception exception) {
            log.error("authToken cypher ", exception)
            return ServiceResponse.error("An unknown error occurred authenticating CipherTrust")
        }
        finally {
            apiClient.shutdownClient()
        }

    }


    @Override
    public String getUsage() {
        StringBuilder usage = new StringBuilder();

        usage.append("This allows cyphers to use Thales CipherTrust Manager. This can be configured in the plugin integration settings.");

        return usage.toString();
    }

    @Override
    public String getHTMLUsage() {
        return null;
    }


    @Override
    Boolean readFromDatastore() {
        return false //important to ensure reads are always obtained from ciphertrust
    }
}
