# EzsignsignaturepaymentdetailResponseCompound

An Ezsignsignaturepaymentdetail Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignsignaturepaymentdetailID** | **number** | The unique ID of the Ezsignsignaturepaymentdetail | [default to undefined]
**fkiGlaccountcontainerID** | **number** | The unique ID of the Glaccountcontainer | [optional] [default to undefined]
**tEzsignsignaturepaymentdetailDescription** | **string** | A description for the Ezsignsignaturepaymentdetail. | [default to undefined]
**dEzsignsignaturepaymentdetailAmount** | **string** | The amount of the for the Ezsignsignaturepaymentdetail | [default to undefined]
**eEzsignsignaturepaymentdetailTaxable** | [**FieldEEzsignsignaturepaymentdetailTaxable**](FieldEEzsignsignaturepaymentdetailTaxable.md) |  | [default to undefined]

## Example

```typescript
import { EzsignsignaturepaymentdetailResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignsignaturepaymentdetailResponseCompound = {
    pkiEzsignsignaturepaymentdetailID,
    fkiGlaccountcontainerID,
    tEzsignsignaturepaymentdetailDescription,
    dEzsignsignaturepaymentdetailAmount,
    eEzsignsignaturepaymentdetailTaxable,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
