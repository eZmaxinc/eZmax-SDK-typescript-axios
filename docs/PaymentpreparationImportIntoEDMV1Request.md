# PaymentpreparationImportIntoEDMV1Request

Request for POST /1/object/paymentpreparation/{pkiPaymentpreparationID}/importIntoEDM

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**a_objAttachment** | [**Array&lt;CustomAttachmentImportIntoEDMRequest&gt;**](CustomAttachmentImportIntoEDMRequest.md) |  | [default to undefined]

## Example

```typescript
import { PaymentpreparationImportIntoEDMV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: PaymentpreparationImportIntoEDMV1Request = {
    a_objAttachment,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
