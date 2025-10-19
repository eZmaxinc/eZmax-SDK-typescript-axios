# BillingentityinternalproductResponse

A Billingentityinternalproduct Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiBillingentityinternalproductID** | **number** | The unique ID of the Billingentityinternalproduct | [default to undefined]
**fkiBillingentityinternalID** | **number** | The unique ID of the Billingentityinternal. | [default to undefined]
**sBillingentityinternalDescriptionX** | **string** | The description of the Billingentityinternal in the language of the requester | [default to undefined]
**fkiEzmaxproductID** | **number** | The unique ID of the Ezmaxproduct | [default to undefined]
**sEzmaxproductDescriptionX** | **string** | The description of the Ezmaxproduct in the language of the requester | [default to undefined]
**fkiBillingentityexternalID** | **number** | The unique ID of the Billingentityexternal | [default to undefined]
**sBillingentityexternalDescription** | **string** | The description of the Billingentityexternal | [default to undefined]

## Example

```typescript
import { BillingentityinternalproductResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: BillingentityinternalproductResponse = {
    pkiBillingentityinternalproductID,
    fkiBillingentityinternalID,
    sBillingentityinternalDescriptionX,
    fkiEzmaxproductID,
    sEzmaxproductDescriptionX,
    fkiBillingentityexternalID,
    sBillingentityexternalDescription,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
