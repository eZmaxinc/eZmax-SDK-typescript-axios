# UsergroupdelegationResponse

A Usergroupdelegation Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiUsergroupdelegationID** | **number** | The unique ID of the Usergroupdelegation | [default to undefined]
**fkiUsergroupID** | **number** | The unique ID of the Usergroup | [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [default to undefined]
**sUserFirstname** | **string** | The first name of the user | [default to undefined]
**sUserLastname** | **string** | The last name of the user | [default to undefined]
**sUserLoginname** | **string** | The login name of the User. | [default to undefined]
**sEmailAddress** | **string** | The email address. | [optional] [default to undefined]
**bUserIsactive** | **boolean** | Whether the User is active or not | [default to undefined]
**sUsergroupNameX** | **string** | The Name of the Usergroup in the language of the requester | [default to undefined]

## Example

```typescript
import { UsergroupdelegationResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: UsergroupdelegationResponse = {
    pkiUsergroupdelegationID,
    fkiUsergroupID,
    fkiUserID,
    sUserFirstname,
    sUserLastname,
    sUserLoginname,
    sEmailAddress,
    bUserIsactive,
    sUsergroupNameX,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
