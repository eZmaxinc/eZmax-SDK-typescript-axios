# EzsignuserResponse

A Ezsignuser Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignuserID** | **number** | The unique ID of the Ezsignuser | [default to undefined]
**fkiContactID** | **number** | The unique ID of the Contact | [default to undefined]
**objContact** | [**ContactResponseCompound**](ContactResponseCompound.md) |  | [default to undefined]
**objAudit** | [**CommonAudit**](CommonAudit.md) |  | [default to undefined]

## Example

```typescript
import { EzsignuserResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignuserResponse = {
    pkiEzsignuserID,
    fkiContactID,
    objContact,
    objAudit,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
