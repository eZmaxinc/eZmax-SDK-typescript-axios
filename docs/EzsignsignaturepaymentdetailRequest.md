# EzsignsignaturepaymentdetailRequest

An Ezsignsignaturepaymentdetail Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignsignaturepaymentdetailID** | **number** | The unique ID of the Ezsignsignaturepaymentdetail | [optional] [default to undefined]
**fkiGlaccountcontainerID** | **number** | The unique ID of the Glaccountcontainer | [default to undefined]
**tEzsignsignaturepaymentdetailDescription** | **string** | A description for the Ezsignsignaturepaymentdetail. | [default to undefined]
**dEzsignsignaturepaymentdetailAmount** | **string** | The amount of the for the Ezsignsignaturepaymentdetail | [default to undefined]
**eEzsignsignaturepaymentdetailTaxable** | [**FieldEEzsignsignaturepaymentdetailTaxable**](FieldEEzsignsignaturepaymentdetailTaxable.md) |  | [default to undefined]

## Example

```typescript
import { EzsignsignaturepaymentdetailRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignsignaturepaymentdetailRequest = {
    pkiEzsignsignaturepaymentdetailID,
    fkiGlaccountcontainerID,
    tEzsignsignaturepaymentdetailDescription,
    dEzsignsignaturepaymentdetailAmount,
    eEzsignsignaturepaymentdetailTaxable,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
