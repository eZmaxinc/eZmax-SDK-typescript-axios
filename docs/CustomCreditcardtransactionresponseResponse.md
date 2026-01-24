# CustomCreditcardtransactionresponseResponse

A custom Creditcardtransactionresponse Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**sCreditcardtransactionISOcode** | **string** | The ISO code | [default to undefined]
**sCreditcardtransactionResponsecode** | **string** | The response code | [default to undefined]
**sCreditcardtransactionResponseterminalmessage** | **string** | The terminal response message | [default to undefined]
**eCreditcardtransactionAvsresult** | [**FieldECreditcardtransactionAvsresult**](FieldECreditcardtransactionAvsresult.md) |  | [optional] [default to undefined]
**eCreditcardtransactionCvdresult** | [**FieldECreditcardtransactionCvdresult**](FieldECreditcardtransactionCvdresult.md) |  | [optional] [default to undefined]

## Example

```typescript
import { CustomCreditcardtransactionresponseResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomCreditcardtransactionresponseResponse = {
    sCreditcardtransactionISOcode,
    sCreditcardtransactionResponsecode,
    sCreditcardtransactionResponseterminalmessage,
    eCreditcardtransactionAvsresult,
    eCreditcardtransactionCvdresult,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
