# EzsignsignatureSignV1ResponseMPayload

Response for POST /1/object/ezsignsignature/{pkiEzsignsignatureID}/sign

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**dtEzsignsignatureDateInFolderTimezone** | **string** | The date the Ezsignsignature was signed in folder\&#39;s timezone | [default to undefined]
**objTimezone** | [**CustomTimezoneWithCodeResponse**](CustomTimezoneWithCodeResponse.md) |  | [optional] [default to undefined]
**objCreditcardtransaction** | [**CustomCreditcardtransactionResponse**](CustomCreditcardtransactionResponse.md) |  | [optional] [default to undefined]

## Example

```typescript
import { EzsignsignatureSignV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignsignatureSignV1ResponseMPayload = {
    dtEzsignsignatureDateInFolderTimezone,
    objTimezone,
    objCreditcardtransaction,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
