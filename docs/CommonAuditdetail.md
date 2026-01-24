# CommonAuditdetail

Gives informations about the user that created the object or the last user to have modified it.  If the object was never modified after creation, both Created and Modified informations will be the same. 

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiUserID** | **number** | The unique ID of the User | [default to undefined]
**fkiApikeyID** | **number** | The unique ID of the Apikey | [optional] [default to undefined]
**sUserLoginname** | **string** | The login name of the User. | [default to undefined]
**sUserLastname** | **string** | The last name of the user | [default to undefined]
**sUserFirstname** | **string** | The first name of the user | [default to undefined]
**sApikeyDescriptionX** | **string** | The description of the Apikey in the language of the requester | [optional] [default to undefined]
**dtAuditdetailDate** | **string** | Represent a Date Time. The timezone is the one configured in the User\&#39;s profile. | [default to undefined]

## Example

```typescript
import { CommonAuditdetail } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommonAuditdetail = {
    fkiUserID,
    fkiApikeyID,
    sUserLoginname,
    sUserLastname,
    sUserFirstname,
    sApikeyDescriptionX,
    dtAuditdetailDate,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
