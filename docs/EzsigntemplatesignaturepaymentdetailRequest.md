# EzsigntemplatesignaturepaymentdetailRequest

An Ezsigntemplatesignaturepaymentdetail Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplatesignaturepaymentdetailID** | **number** | The unique ID of the Ezsignsignaturepaymentdetail | [optional] [default to undefined]
**fkiGlaccountcontainerID** | **number** | The unique ID of the Glaccountcontainer | [default to undefined]
**tEzsigntemplatesignaturepaymentdetailDescription** | **string** | A description for the Ezsignsignaturepaymentdetail. | [default to undefined]
**dEzsigntemplatesignaturepaymentdetailAmount** | **string** | The amount of the for the Ezsignsignaturepaymentdetail | [default to undefined]
**eEzsigntemplatesignaturepaymentdetailTaxable** | [**FieldEEzsigntemplatesignaturepaymentdetailTaxable**](FieldEEzsigntemplatesignaturepaymentdetailTaxable.md) |  | [default to undefined]

## Example

```typescript
import { EzsigntemplatesignaturepaymentdetailRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatesignaturepaymentdetailRequest = {
    pkiEzsigntemplatesignaturepaymentdetailID,
    fkiGlaccountcontainerID,
    tEzsigntemplatesignaturepaymentdetailDescription,
    dEzsigntemplatesignaturepaymentdetailAmount,
    eEzsigntemplatesignaturepaymentdetailTaxable,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
