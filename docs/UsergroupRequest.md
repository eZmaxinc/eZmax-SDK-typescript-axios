# UsergroupRequest

A Usergroup Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiUsergroupID** | **number** | The unique ID of the Usergroup | [optional] [default to undefined]
**objEmail** | [**EmailRequest**](EmailRequest.md) |  | [optional] [default to undefined]
**objUsergroupName** | [**MultilingualUsergroupName**](MultilingualUsergroupName.md) |  | [default to undefined]

## Example

```typescript
import { UsergroupRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: UsergroupRequest = {
    pkiUsergroupID,
    objEmail,
    objUsergroupName,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
