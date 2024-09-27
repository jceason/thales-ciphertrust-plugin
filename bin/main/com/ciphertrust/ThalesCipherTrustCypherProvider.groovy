package com.ciphertrust

import com.morpheusdata.core.CypherModuleProvider
import com.morpheusdata.core.MorpheusContext
import com.morpheusdata.core.Plugin
import com.morpheusdata.cypher.CypherModule

class ThalesCipherTrustCypherProvider implements CypherModuleProvider{
    MorpheusContext morpheusContext
    Plugin plugin
    String code = 'ciphertrust-cypher'

    ThalesCipherTrustCypherProvider(Plugin plugin, MorpheusContext morpheusContext) {
        this.plugin = plugin
        this.morpheusContext = morpheusContext
    }

    /**
     * An implementation of a CypherModule for reading and writing data patterns
     * @return a cypher module
     */
    @Override
    CypherModule getCypherModule() {
        ThalesCipherTrustCypherModule module = new ThalesCipherTrustCypherModule()
        module.setMorpheusContext(this.morpheusContext)
        module.setPlugin(this.plugin)
        return module
    }

    /**
     * The mount prefix point for which this module should be registered to cypher's backend.
     * @return a String path prefix
    */
    @Override
    String getCypherMountPoint() {
        return 'ciphertrust'
    }

    /**
     * Returns the Morpheus Context for interacting with data stored in the Main Morpheus Application
     *
     * @return an implementation of the MorpheusContext for running Future based rxJava queries
     */
    @Override
    MorpheusContext getMorpheus() {
        return morpheusContext
    }

    /**
     * A unique shortcode used for referencing the provided provider. Make sure this is going to be unique as any data
     * that is seeded or generated related to this provider will reference it by this code.
     * @return short code string that should be unique across all other plugin implementations.
     */
    @Override
    String getCode() {
        return this.code
    }

    /**
     * Provides the provider name for reference when adding to the Morpheus Orchestrator
     * NOTE: This may be useful to set as an i18n key for UI reference and localization support.
     *
     * @return either an English name of a Provider or an i18n based key that can be scanned for in a properties file.
     */
    @Override
    String getName() {
        return 'CipherTrust Cypher'
    }
}
