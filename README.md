## Thales CipherTrust Plugin

This is a Morpheus plugin for using Thales CipherTrust key management and secret management.

Testing and development was performed using:
CipherTrust Manager 2.17
Morpheus v7.0.4


### Building

This is a Morpheus plugin that leverages the `morpheus-plugin-core` which can be referenced by visiting [https://developer.morpheusdata.com](https://developer.morpheusdata.com). It is a groovy plugin designed to be uploaded into a Morpheus environment via the `Administration -> Integrations -> Plugins` section. 

To build this product from scratch simply run the shadowJar gradle task on java 11:

```bash
./gradlew shadowJar
```

A jar will be produced in the `build/lib` folder that can be uploaded into a Morpheus environment.
Example:


### Loading
Navigate to the follow Morpheus page to upload the plugin.
Administration > plugin > add 
This will allow you to upload the plugin from the local system.

<img width="733" height="185" alt="image" src="https://github.com/user-attachments/assets/d4699bcb-88f8-400a-8a8b-32b80d4006f4" />


### Plugin Settings for Key Management(Cypher)
Under Administration > plugin > Thales CipherTrust > Edit
<img width="1125" height="128" alt="image" src="https://github.com/user-attachments/assets/2be9a80f-09ea-4fea-af96-bc37c8cfa700" />

1.	URL:  The CipherTrust URL endpoint
2.	USERNAME:  Username with authority to manage keys for the domain
3.	PASSWORD:  The password for username above
4.	DOMAIN: root is the default domain, however if another domain is being used that can be specified here.

<img width="616" height="570" alt="image" src="https://github.com/user-attachments/assets/80b3a968-af22-416b-b4d6-6cb8de914d55" />


### Plugin Settings for Secrets Management(Credential)
Please note you will need to have an Akeyless API Access ID and Key already created in the Akeyless console with authority to for secrets management.  If not already done configure Akeyless Secrets Management in CipherTrust Manager. 

Credential configuration is separate than Cypher.  To configure Credential plugin settings, navigate to the following. 
Infrastructure > Trust > Integrations > ADD
Then select CipherTrust

<img width="735" height="234" alt="image" src="https://github.com/user-attachments/assets/5cb8b3ec-ebd7-4d9c-ad3c-46d13e5a78f9" />

1.	NAME: CipherTrust
2.	URL:  The CipherTrust Secrets Management URL endpoint, note ends in akeyless-api/
3.	ACCESS ID:  The API access id for secrets management
4.	PASSWORD:  The API access key for secrets management 
5.	SECRET Path : morpheus-credentials is the default, however if another directory can be specified to store secrets created from Morpheus 

<img width="582" height="468" alt="image" src="https://github.com/user-attachments/assets/efe124e8-58db-4878-aaa3-e321c66f952b" />



