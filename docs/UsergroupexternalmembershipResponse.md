# UsergroupexternalmembershipResponse

A Usergroupexternalmembership Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiUsergroupexternalmembershipID** | **number** | The unique ID of the Usergroupexternalmembership | [default to undefined]
**fkiUsergroupexternalID** | **number** | The unique ID of the Usergroupexternal | [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [default to undefined]
**sUserFirstname** | **string** | The first name of the user | [default to undefined]
**sUserLastname** | **string** | The last name of the user | [default to undefined]
**sUserLoginname** | **string** | The login name of the User. | [default to undefined]
**sEmailAddress** | **string** | The email address. | [default to undefined]
**sUsergroupexternalName** | **string** | The name of the Usergroupexternal | [default to undefined]

## Example

```typescript
import { UsergroupexternalmembershipResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: UsergroupexternalmembershipResponse = {
    pkiUsergroupexternalmembershipID,
    fkiUsergroupexternalID,
    fkiUserID,
    sUserFirstname,
    sUserLastname,
    sUserLoginname,
    sEmailAddress,
    sUsergroupexternalName,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
