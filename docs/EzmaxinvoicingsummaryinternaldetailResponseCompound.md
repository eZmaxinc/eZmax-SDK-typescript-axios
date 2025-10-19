# EzmaxinvoicingsummaryinternaldetailResponseCompound

A Ezmaxinvoicingsummaryinternaldetail Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzmaxinvoicingsummaryinternaldetailID** | **number** | The unique ID of the Ezmaxinvoicingsummaryinternaldetail | [optional] [default to undefined]
**fkiEzmaxinvoicingsummaryinternalID** | **number** | The unique ID of the Ezmaxinvoicingsummaryinternal | [optional] [default to undefined]
**fkiEzmaxproductID** | **number** | The unique ID of the Ezmaxproduct | [default to undefined]
**sEzmaxproductDescriptionX** | **string** | The description of the Ezmaxproduct in the language of the requester | [default to undefined]
**fkiBillingentityexternalID** | **number** | The unique ID of the Billingentityexternal | [default to undefined]
**sBillingentityexternalDescription** | **string** | The description of the Billingentityexternal | [default to undefined]
**dEzmaxinvoicingsummaryinternaldetailCountreal** | **string** | The count item invoiced for the product | [default to undefined]
**dEzmaxinvoicingsummaryinternaldetailSubtotal** | **string** | The subtotal invoiced for the product | [default to undefined]
**dEzmaxinvoicingsummaryinternaldetailRebate** | **string** | The rebate for the product | [default to undefined]
**dEzmaxinvoicingsummaryinternaldetailTotal** | **string** | The total invoiced for the product | [default to undefined]
**bEzmaxinvoicingsummaryinternaldetailAdjustment** | **boolean** | Whether if it\&#39;s an adjustment | [default to undefined]
**tEzmaxproductHelpX** | **string** | The help message of the Ezmaxproduct in the language of the requester | [default to undefined]

## Example

```typescript
import { EzmaxinvoicingsummaryinternaldetailResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzmaxinvoicingsummaryinternaldetailResponseCompound = {
    pkiEzmaxinvoicingsummaryinternaldetailID,
    fkiEzmaxinvoicingsummaryinternalID,
    fkiEzmaxproductID,
    sEzmaxproductDescriptionX,
    fkiBillingentityexternalID,
    sBillingentityexternalDescription,
    dEzmaxinvoicingsummaryinternaldetailCountreal,
    dEzmaxinvoicingsummaryinternaldetailSubtotal,
    dEzmaxinvoicingsummaryinternaldetailRebate,
    dEzmaxinvoicingsummaryinternaldetailTotal,
    bEzmaxinvoicingsummaryinternaldetailAdjustment,
    tEzmaxproductHelpX,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
