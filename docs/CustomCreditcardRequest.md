# CustomCreditcardRequest

A Custom Creditcard Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fksCreditcardtokenID** | **string** | The creditcard token identifier | [default to undefined]
**sCreditcardCVV** | **string** | The creditcard card CVV | [default to undefined]
**objCreditcarddetail** | [**CreditcarddetailRequest**](CreditcarddetailRequest.md) |  | [default to undefined]

## Example

```typescript
import { CustomCreditcardRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomCreditcardRequest = {
    fksCreditcardtokenID,
    sCreditcardCVV,
    objCreditcarddetail,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
