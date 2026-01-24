# UserCreateEzsignuserV1ResponseMPayload

Payload for POST /1/module/user/createEzsignuser

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**a_sEmailAddressSuccess** | **Array&lt;string&gt;** | An array of email addresses that succeeded. | [default to undefined]
**a_sEmailAddressFailure** | **Array&lt;string&gt;** | An array of email addresses that failed. | [default to undefined]

## Example

```typescript
import { UserCreateEzsignuserV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: UserCreateEzsignuserV1ResponseMPayload = {
    a_sEmailAddressSuccess,
    a_sEmailAddressFailure,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
