# UsergroupmembershipResponse

A Usergroupmembership Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiUsergroupmembershipID** | **number** | The unique ID of the Usergroupmembership | [default to undefined]
**fkiUsergroupID** | **number** | The unique ID of the Usergroup | [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiUsergroupexternalID** | **number** | The unique ID of the Usergroupexternal | [optional] [default to undefined]
**sUserFirstname** | **string** | The first name of the user | [optional] [default to undefined]
**sUserLastname** | **string** | The last name of the user | [optional] [default to undefined]
**sUserLoginname** | **string** | The login name of the User. | [optional] [default to undefined]
**sEmailAddress** | **string** | The email address. | [optional] [default to undefined]
**sUsergroupNameX** | **string** | The Name of the Usergroup in the language of the requester | [default to undefined]
**sUsergroupexternalName** | **string** | The name of the Usergroupexternal | [optional] [default to undefined]

## Example

```typescript
import { UsergroupmembershipResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: UsergroupmembershipResponse = {
    pkiUsergroupmembershipID,
    fkiUsergroupID,
    fkiUserID,
    fkiUsergroupexternalID,
    sUserFirstname,
    sUserLastname,
    sUserLoginname,
    sEmailAddress,
    sUsergroupNameX,
    sUsergroupexternalName,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
