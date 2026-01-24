# CommonResponseErrorCreditcardValidation

Generic Error Message

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**sErrorMessage** | **string** | The message giving details about the error | [default to undefined]
**eErrorCode** | [**FieldEErrorCode**](FieldEErrorCode.md) |  | [default to undefined]
**a_sErrorMessagedetail** | **Array&lt;string&gt;** | More error message detail | [optional] [default to undefined]
**objCreditcardtransactionresponse** | [**CustomCreditcardtransactionresponseResponse**](CustomCreditcardtransactionresponseResponse.md) |  | [optional] [default to undefined]

## Example

```typescript
import { CommonResponseErrorCreditcardValidation } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommonResponseErrorCreditcardValidation = {
    sErrorMessage,
    eErrorCode,
    a_sErrorMessagedetail,
    objCreditcardtransactionresponse,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
