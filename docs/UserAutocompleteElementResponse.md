# UserAutocompleteElementResponse

A User AutocompleteElement Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**eUserType** | [**FieldEUserType**](FieldEUserType.md) |  | [default to undefined]
**sUserName** | **string** | The description of the User in the language of the requester | [default to undefined]
**pkiUserID** | **number** | The unique ID of the User | [default to undefined]
**bUserIsactive** | **boolean** | Whether the User is active or not | [default to undefined]

## Example

```typescript
import { UserAutocompleteElementResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: UserAutocompleteElementResponse = {
    eUserType,
    sUserName,
    pkiUserID,
    bUserIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
