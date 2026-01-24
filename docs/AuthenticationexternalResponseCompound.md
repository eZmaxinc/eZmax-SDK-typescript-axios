# AuthenticationexternalResponseCompound

A Authenticationexternal Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiAuthenticationexternalID** | **number** | The unique ID of the Authenticationexternal | [default to undefined]
**sAuthenticationexternalDescription** | **string** | The description of the Authenticationexternal | [default to undefined]
**eAuthenticationexternalType** | [**FieldEAuthenticationexternalType**](FieldEAuthenticationexternalType.md) |  | [default to undefined]
**bAuthenticationexternalConnected** | **boolean** | Whether the Authenticationexternal has been connected or not | [optional] [default to undefined]
**sAuthenticationexternalAuthorizationurl** | **string** | The url to authorize the Authenticationexternal | [optional] [default to undefined]
**objAudit** | [**CommonAudit**](CommonAudit.md) |  | [default to undefined]

## Example

```typescript
import { AuthenticationexternalResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: AuthenticationexternalResponseCompound = {
    pkiAuthenticationexternalID,
    sAuthenticationexternalDescription,
    eAuthenticationexternalType,
    bAuthenticationexternalConnected,
    sAuthenticationexternalAuthorizationurl,
    objAudit,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
