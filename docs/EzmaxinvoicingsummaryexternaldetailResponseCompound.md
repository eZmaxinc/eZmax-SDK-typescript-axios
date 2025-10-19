# EzmaxinvoicingsummaryexternaldetailResponseCompound

A Ezmaxinvoicingsummaryexternaldetail Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzmaxinvoicingsummaryexternaldetailID** | **number** | The unique ID of the Ezmaxinvoicingsummaryexternaldetail | [optional] [default to undefined]
**fkiEzmaxinvoicingsummaryexternalID** | **number** | The unique ID of the Ezmaxinvoicingsummaryexternal | [optional] [default to undefined]
**fkiEzmaxproductID** | **number** | The unique ID of the Ezmaxproduct | [default to undefined]
**sEzmaxproductDescriptionX** | **string** | The description of the Ezmaxproduct in the language of the requester | [default to undefined]
**dEzmaxinvoicingsummaryexternaldetailCountreal** | **string** | The count item invoiced for the product | [default to undefined]
**dEzmaxinvoicingsummaryexternaldetailSubtotal** | **string** | The subtotal invoiced for the product | [default to undefined]
**dEzmaxinvoicingsummaryexternaldetailRebate** | **string** | The rebate for the product | [default to undefined]
**dEzmaxinvoicingsummaryexternaldetailTotal** | **string** | The total invoiced for the product | [default to undefined]
**bEzmaxinvoicingsummaryexternaldetailAdjustment** | **boolean** | Whether it\&#39;s an adjustment | [default to undefined]
**tEzmaxproductHelpX** | **string** | The help message of the Ezmaxproduct in the language of the requester | [default to undefined]

## Example

```typescript
import { EzmaxinvoicingsummaryexternaldetailResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzmaxinvoicingsummaryexternaldetailResponseCompound = {
    pkiEzmaxinvoicingsummaryexternaldetailID,
    fkiEzmaxinvoicingsummaryexternalID,
    fkiEzmaxproductID,
    sEzmaxproductDescriptionX,
    dEzmaxinvoicingsummaryexternaldetailCountreal,
    dEzmaxinvoicingsummaryexternaldetailSubtotal,
    dEzmaxinvoicingsummaryexternaldetailRebate,
    dEzmaxinvoicingsummaryexternaldetailTotal,
    bEzmaxinvoicingsummaryexternaldetailAdjustment,
    tEzmaxproductHelpX,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
