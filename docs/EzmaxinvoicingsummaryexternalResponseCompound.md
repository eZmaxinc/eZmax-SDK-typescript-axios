# EzmaxinvoicingsummaryexternalResponseCompound

A Ezmaxinvoicingsummaryexternal Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzmaxinvoicingsummaryexternalID** | **number** | The unique ID of the Ezmaxinvoicingsummaryexternal | [optional] [default to undefined]
**fkiEzmaxinvoicingID** | **number** | The unique ID of the Ezmaxinvoicing | [optional] [default to undefined]
**fkiBillingentityexternalID** | **number** | The unique ID of the Billingentityexternal | [default to undefined]
**sBillingentityexternalDescription** | **string** | The description of the Billingentityexternal | [default to undefined]
**sEzmaxinvoicingsummaryexternalDescription** | **string** | The description of the Ezmaxinvoicingsummaryexternal | [default to undefined]
**a_objEzmaxinvoicingsummaryexternaldetail** | [**Array&lt;EzmaxinvoicingsummaryexternaldetailResponseCompound&gt;**](EzmaxinvoicingsummaryexternaldetailResponseCompound.md) |  | [default to undefined]

## Example

```typescript
import { EzmaxinvoicingsummaryexternalResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzmaxinvoicingsummaryexternalResponseCompound = {
    pkiEzmaxinvoicingsummaryexternalID,
    fkiEzmaxinvoicingID,
    fkiBillingentityexternalID,
    sBillingentityexternalDescription,
    sEzmaxinvoicingsummaryexternalDescription,
    a_objEzmaxinvoicingsummaryexternaldetail,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
