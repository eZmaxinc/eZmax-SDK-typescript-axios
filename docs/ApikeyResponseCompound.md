# ApikeyResponseCompound

An Apikey Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiApikeyID** | **number** | The unique ID of the Apikey | [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [default to undefined]
**fkiEzmaxpartnerproductstageID** | **number** | The unique ID of the Ezmaxpartnerproductstage | [optional] [default to undefined]
**objApikeyDescription** | [**MultilingualApikeyDescription**](MultilingualApikeyDescription.md) |  | [default to undefined]
**objContactName** | [**CustomContactNameResponse**](CustomContactNameResponse.md) |  | [default to undefined]
**sApikeyApikey** | **string** | The Apikey for the API key.  This will be hidden if we are not creating or regenerating the Apikey. | [optional] [default to undefined]
**sApikeySecret** | **string** | The Secret for the API key.  This will be hidden if we are not creating or regenerating the Apikey. | [optional] [default to undefined]
**bApikeyIsactive** | **boolean** | Whether the apikey is active or not | [default to undefined]
**bApikeyIssigned** | **boolean** | Whether the apikey is signed or not | [optional] [default to undefined]
**objAudit** | [**CommonAudit**](CommonAudit.md) |  | [default to undefined]

## Example

```typescript
import { ApikeyResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ApikeyResponseCompound = {
    pkiApikeyID,
    fkiUserID,
    fkiEzmaxpartnerproductstageID,
    objApikeyDescription,
    objContactName,
    sApikeyApikey,
    sApikeySecret,
    bApikeyIsactive,
    bApikeyIssigned,
    objAudit,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
