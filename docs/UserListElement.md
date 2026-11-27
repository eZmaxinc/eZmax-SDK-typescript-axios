# UserListElement

A User List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiUserID** | **number** | The unique ID of the User | [default to undefined]
**fkiAgentID** | **number** | The unique ID of the Agent. | [optional] [default to undefined]
**fkiBrokerID** | **number** | The unique ID of the Broker. | [optional] [default to undefined]
**sUserFirstname** | **string** | The first name of the user | [default to undefined]
**sUserLastname** | **string** | The last name of the user | [default to undefined]
**sUserLoginname** | **string** | The login name of the User. | [default to undefined]
**bUserIsactive** | **boolean** | Whether the User is active or not | [default to undefined]
**bUserSuspended** | **boolean** | Whether the User is suspended or not | [optional] [default to undefined]
**eUserType** | [**FieldEUserType**](FieldEUserType.md) |  | [default to undefined]
**eUserOrigin** | [**FieldEUserOrigin**](FieldEUserOrigin.md) |  | [default to undefined]
**eUserEzsignaccess** | [**FieldEUserEzsignaccess**](FieldEUserEzsignaccess.md) |  | [default to undefined]
**dtUserEzsignprepaidexpiration** | **string** | The eZsign prepaid expiration date | [optional] [default to undefined]
**sEmailAddress** | **string** | The email address. | [default to undefined]
**sUserJobtitle** | **string** | The job title of the user | [optional] [default to undefined]

## Example

```typescript
import { UserListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: UserListElement = {
    pkiUserID,
    fkiAgentID,
    fkiBrokerID,
    sUserFirstname,
    sUserLastname,
    sUserLoginname,
    bUserIsactive,
    bUserSuspended,
    eUserType,
    eUserOrigin,
    eUserEzsignaccess,
    dtUserEzsignprepaidexpiration,
    sEmailAddress,
    sUserJobtitle,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
