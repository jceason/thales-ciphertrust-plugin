/*
* Copyright 2022 the original author or authors.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package com.ciphertrust

import com.morpheusdata.core.Plugin
import com.morpheusdata.model.OptionType
import groovy.util.logging.Slf4j
import groovy.json.*
import com.morpheusdata.core.MorpheusContext

/**
 * @author Jeff Ceason
 */
@Slf4j
class ThalesCipherTrustPlugin extends Plugin {


	@Override
	String getCode() {
		return 'thales-ciphertrust-plugin'
	}

	@Override
	void initialize() {

                this.setName("Thales CipherTrust")
                this.setDescription("Thales CipherTrust Plugin")
                this.setAuthor("Thales")

                ThalesCipherTrustCredentialProvider cipherTrustCredentialProvider = new ThalesCipherTrustCredentialProvider(this, morpheus)
	            this.pluginProviders.put("ciphertrust" ,cipherTrustCredentialProvider)

                ThalesCipherTrustCypherProvider     cipherTrustCypherProvider = new ThalesCipherTrustCypherProvider(this, morpheus)
                this.pluginProviders.put("ciphertrust-cypher", cipherTrustCypherProvider)

                //works below
                //this.registerProvider(new ThalesCipherTrustCredentialProvider(this,this.morpheus))
                //this.registerProvider(new ThalesCipherTrustCypherProvider(this,this.morpheus))

				/* 
                ThalesCipherTrustCredentialProvider thalesCipherTrustCredentialProvider new ThalesCipherTrustCredentialProvider(this, morpheus)
	            this.pluginProviders.put('ciphertrust' thalesCipherTrustCredentialProvider)
                ThalesCipherTrustCypherProvider thalesCipherTrustCypherProvider new ThalesCipherTrustCypherProvider(this, morpheus)
	            this.pluginProviders.put(thalesCipherTrustCypherProvider.getCode(), thalesCipherTrustCypherProvider)
                /*     
 

                ThalesCipherTrustCredentialProvider  thalesCipherTrustCredentialProvider new ThalesCipherTrustCredentialProvider (this,this.morpheus)
	        this.pluginProviders.put("ciphertrust", thalesCipherTrustCredentialProvider)
                this.pluginProviders.put("ciphertrust-cypher", new ThalesCiphertrustCypherProvider(this,this.morpheus))

               this.registerProvider(new ThalesCipherTrustCypherProvider(this,morpheus))
               this.registerProvider(new ThalesCipherTrustCredentialProvider(this,morpheus))
               */

	       //this.pluginProviders.put("ciphertrust-cypher", ThalesCipherTrustCypherProvider)
	       //this.pluginProviders.put("ciphertrust", ThalesCipherTrustCredentialProvider)


         this.settings << new OptionType (
                name: 'Thales CipherTrust Service Url',
                code: 'ciphertrust-cypher-plugin-url',
                fieldName: 'cipherTrustPluginServiceUrl',
                displayOrder: 0,
                fieldLabel: 'Thales CipherTrust Url',
                helpText: 'The full URL of the Thales CipherTrust Manager endpoint. Example: https://ciphertrust.domain/akeyless-api/',
                required: true,
                inputType: OptionType.InputType.TEXT
        )
        this.settings << new OptionType (
                name: 'Thales CipherTrust API Access Id',
                code: 'ciphertrust-cypher-plugin-accessid',
                fieldName: 'cipherTrustPluginAccessId',
                displayOrder: 1,
                fieldLabel: 'Thales CipherTrust Access Id',
                helpText: 'The Thales CipherTrust API Access Id',
                required: true,
                inputType: OptionType.InputType.TEXT
        )
        this.settings << new OptionType (
                name: 'Thales CipherTrust API Access Key',
                code: 'ciphertrust-cypher-plugin-accesskey',
                fieldName: 'cipherTrustPluginAccessKey',
                displayOrder: 2,
                fieldLabel: 'Thales CipherTrust API Access Key',
                helpText: 'The Thales CipherTrust API Access Key',
                required: true,
                inputType: OptionType.InputType.PASSWORD
        )
        this.settings << new OptionType (
                name: 'Thales CipherTrust API Secret Path',
                code: 'ciphertrust-cypher-plugin-secretPath',
                fieldName: 'cipherTrustPluginSecretPath',
                displayOrder: 3,
                fieldLabel: 'Thales CipherTrust API Secret Path',
                helpText: 'The Thales CipherTrust API Secret Path',
                required: false,
                inputType: OptionType.InputType.TEXT
        )

	}

	/**
	 * Called when a plugin is being removed from the plugin manager (aka Uninstalled)
	 */
	@Override
	void onDestroy() {
		//nothing to do for now
	}
	
	public  String getUrl() {
		def rtn
		def settings = getSettings(this.morpheus, this)
		if (settings.cipherTrustPluginServiceUrl) {
			rtn = settings.cipherTrustPluginServiceUrl
		}
		return rtn
	}

	public String getAccessId() {
		def rtn
		def settings = getSettings(this.morpheus, this)
		if (settings.cipherTrustPluginAccessId) {
			rtn = settings.cipherTrustPluginAccessId
		}
		return rtn
	}

	public String getAccessKey() {
		def rtn
		def settings = getSettings(this.morpheus, this)
		if (settings.cipherTrustPluginAccessKey) {
			rtn = settings.cipherTrustPluginAccessKey
		}
		return rtn
	}

	public String getSecretPath() {
		def rtn
		def settings = getSettings(this.morpheus, this)
		if (settings.cipherTrustPluginSecretPath) {
			rtn = settings.cipherTrustPluginSecretPath
		}
		return rtn
	}


	private getSettings(MorpheusContext morpheusContext, Plugin plugin) {
		def settingsOutput = null
		try {
			def settings = morpheusContext.getSettings(plugin)
			settings.subscribe(
				{ outData -> 
					settingsOutput = outData
				},
				{ error ->
				  log.error("Error subscribing to settings")
				}
			)
		} catch(Exception e) {
			log.error("Error obtaining Conjur plugin settings")
		}
		if (settingsOutput) {
			JsonSlurper slurper = new JsonSlurper()
			return slurper.parseText(settingsOutput)
		} else {
			return [:]
		}
	}
}
