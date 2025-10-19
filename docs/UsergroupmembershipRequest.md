# UsergroupmembershipRequest

A Usergroupmembership Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiUsergroupmembershipID** | **number** | The unique ID of the Usergroupmembership | [optional] [default to undefined]
**fkiUsergroupID** | **number** | The unique ID of the Usergroup | [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiUsergroupexternalID** | **number** | The unique ID of the Usergroupexternal | [optional] [default to undefined]

## Example

```typescript
import { UsergroupmembershipRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: UsergroupmembershipRequest = {
    pkiUsergroupmembershipID,
    fkiUsergroupID,
    fkiUserID,
    fkiUsergroupexternalID,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
