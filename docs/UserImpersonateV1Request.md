# UserImpersonateV1Request

Request for POST /1/object/user/{pkiUserID}/impersonate

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiUserID** | **number** | The unique ID of the User | [default to undefined]
**iExpirationMinutes** | **number** | The number of minute before key is no longer active | [default to undefined]

## Example

```typescript
import { UserImpersonateV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: UserImpersonateV1Request = {
    fkiUserID,
    iExpirationMinutes,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
