# ApikeyRequest

An Apikey Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiApikeyID** | **number** | The unique ID of the Apikey | [optional] [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [default to undefined]
**objApikeyDescription** | [**MultilingualApikeyDescription**](MultilingualApikeyDescription.md) |  | [default to undefined]
**bApikeyIsactive** | **boolean** | Whether the apikey is active or not | [optional] [default to undefined]
**bApikeyIssigned** | **boolean** | Whether the apikey is signed or not | [optional] [default to undefined]

## Example

```typescript
import { ApikeyRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ApikeyRequest = {
    pkiApikeyID,
    fkiUserID,
    objApikeyDescription,
    bApikeyIsactive,
    bApikeyIssigned,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
