# ApikeyGenerateDelegatedCredentialsV1Request

Request for POST /1/object/apikey/generateDelegatedCredentials

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iExpirationMinutes** | **number** | The number of minute before key is no longer active | [default to undefined]

## Example

```typescript
import { ApikeyGenerateDelegatedCredentialsV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ApikeyGenerateDelegatedCredentialsV1Request = {
    iExpirationMinutes,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
