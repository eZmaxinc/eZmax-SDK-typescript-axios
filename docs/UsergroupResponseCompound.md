# UsergroupResponseCompound

A Usergroup Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiUsergroupID** | **number** | The unique ID of the Usergroup | [default to undefined]
**objUsergroupName** | [**MultilingualUsergroupName**](MultilingualUsergroupName.md) |  | [default to undefined]
**sUsergroupNameX** | **string** | The Name of the Usergroup in the language of the requester | [optional] [default to undefined]
**objEmail** | [**EmailRequest**](EmailRequest.md) |  | [optional] [default to undefined]

## Example

```typescript
import { UsergroupResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: UsergroupResponseCompound = {
    pkiUsergroupID,
    objUsergroupName,
    sUsergroupNameX,
    objEmail,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
