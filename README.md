## Thales CipherTrust Plugin

This is a for interacting with Thales CipherTrust. 

### Building

This is a Morpheus plugin that leverages the `morpheus-plugin-core` which can be referenced by visiting [https://developer.morpheusdata.com](https://developer.morpheusdata.com). It is a groovy plugin designed to be uploaded into a Morpheus environment via the `Administration -> Integrations -> Plugins` section. To build this product from scratch simply run the shadowJar gradle task on java 11:

```bash
./gradlew shadowJar
```

A jar will be produced in the `build/lib` folder that can be uploaded into a Morpheus environment.


### Configuring

Once the plugin is loaded in the environment. Conjur Becomes available in `Infrastructure -> Trust -> Services`.

When adding the integration simply enter the URL of the CipherTrust Server
